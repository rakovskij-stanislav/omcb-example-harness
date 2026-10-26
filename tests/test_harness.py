import base64
import csv
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import zipfile

import harness


def call(name, args, ident="call-1"):
    return {"id": ident, "type": "function", "function": {
        "name": name, "arguments": json.dumps(args)}}


def response(calls=None, finish="tool_calls"):
    return {"choices": [{"finish_reason": finish, "message": {
        "role": "assistant", "content": None, "tool_calls": calls or []}}]}


class FakeClient:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.forced = []

    def complete(self, messages, force_verdict=False):
        self.forced.append(force_verdict)
        item = next(self.responses)
        if isinstance(item, Exception):
            raise item
        return item


class HarnessTests(unittest.TestCase):
    def test_endpoint_normalization(self):
        for endpoint in ("http://localhost:1234", "http://localhost:1234/",
                         "http://localhost:1234/v1", "http://localhost:1234/v1/",
                         "http://localhost:1234/v1/chat/completions"):
            with self.subTest(endpoint=endpoint):
                client = harness.Client(endpoint, "model", "", 10, 100)
                self.assertEqual(client.url, "http://localhost:1234/v1/chat/completions")
        client = harness.Client("http://localhost:1234/custom/v1", "model", "", 10, 100)
        self.assertEqual(client.url, "http://localhost:1234/custom/v1/chat/completions")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / "sample.whl"
        with zipfile.ZipFile(self.archive, "w") as z:
            z.writestr("pkg/setup.py", "raise RuntimeError('must never execute')")
            z.writestr("pkg/binary", b"abc\xff\x00def")
            for i in range(101):
                z.writestr(f"many/{i:03d}.txt", str(i))

    def test_zip_listing_pagination_and_exact_bytes(self):
        archive = harness.Archive(self.archive)
        self.addCleanup(archive.close)
        self.assertEqual([e["path"] for e in archive.listing("")["entries"]], ["many", "pkg"])
        self.assertEqual(archive.listing("many")["next_page"], 1)
        self.assertEqual(len(archive.listing("many", 1)["entries"]), 1)
        self.assertEqual(archive.listing()["total"], 103)
        self.assertEqual(len(archive.listing(page=1)["entries"]), 3)
        result = archive.read("pkg/binary", 2, 4)
        self.assertEqual(base64.b64decode(result["base64"]), b"c\xff\x00d")
        self.assertFalse(result["eof"])
        self.assertEqual(archive.read("pkg/binary", 8, 10)["bytes_read"], 0)
        for path in ("../secret", "/etc/passwd", "pkg/../../secret"):
            with self.assertRaises(ValueError):
                archive.read(path, 0, 10)
        for offset, size in ((-1, 1), (True, 1), (0, 16385), (99, 1)):
            with self.assertRaises(ValueError):
                archive.read("pkg/binary", offset, size)

    def test_tar_bytes_and_no_extraction(self):
        path = self.root / "package.tgz"
        with tarfile.open(path, "w:gz") as tar:
            data = b"console.log('untrusted');"
            info = tarfile.TarInfo("package/index.js")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        archive = harness.Archive(path)
        self.addCleanup(archive.close)
        self.assertEqual(archive.read("package/index.js", 8, 3)["text"], "log")
        self.assertFalse((self.root / "package").exists())

    def test_unsafe_members_are_rejected(self):
        for name, kind in (("../escape", tarfile.REGTYPE),
                           ("hardlink", tarfile.LNKTYPE), ("device", tarfile.CHRTYPE)):
            path = self.root / "unsafe.tar"
            with tarfile.open(path, "w") as tar:
                info = tarfile.TarInfo(name)
                info.type = kind
                info.linkname = "/etc/passwd"
                tar.addfile(info)
            with self.assertRaises(ValueError):
                harness.Archive(path)
        path = self.root / "symlink.zip"
        with zipfile.ZipFile(path, "w") as z:
            info = zipfile.ZipInfo("link")
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            z.writestr(info, "/etc/passwd")
        archive = harness.Archive(path)
        self.addCleanup(archive.close)
        self.assertEqual(archive.listing()["total"], 0)
        self.assertEqual(archive.listing("")["total"], 0)
        with self.assertRaises(ValueError):
            archive.read("link", 0, 10)

    def test_tar_symlinks_are_hidden(self):
        path = self.root / "links.tar.gz"
        with tarfile.open(path, "w:gz") as tar:
            for name, target in (("pkg/README", "README.rst"), ("hidden/link", "/etc/passwd")):
                info = tarfile.TarInfo(name)
                info.type, info.linkname = tarfile.SYMTYPE, target
                tar.addfile(info)
            info = tarfile.TarInfo("pkg/README.rst")
            info.size = 4
            tar.addfile(info, io.BytesIO(b"text"))
        archive = harness.Archive(path)
        self.addCleanup(archive.close)
        self.assertEqual([e["path"] for e in archive.listing()["entries"]], ["pkg/README.rst"])
        self.assertEqual([e["path"] for e in archive.listing("")["entries"]], ["pkg"])
        self.assertEqual([e["path"] for e in archive.listing("pkg")["entries"]], ["pkg/README.rst"])
        self.assertEqual(archive.read("pkg/README.rst", 0, 4)["text"], "text")
        with self.assertRaises(ValueError):
            archive.read("pkg/README", 0, 4)

    def test_tool_loop_and_invalid_call_recovery(self):
        client = FakeClient([
            response([call("read_bytes", {"path": "../oops", "m": 0, "k": 10})]),
            response([call("list_path", {"path": ""}), call("list", {"page": 0}, "call-2")]),
            response([call("read_bytes", {"path": "pkg/setup.py", "m": 0, "k": 100})]),
            response([call("send_verdict", {"verdict": "benign", "reasoning": "No malicious behavior found."})]),
        ])
        messages = []
        result = harness.triage(self.archive, "pypi", client, 10, messages)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["turns"], 4)
        self.assertIn("error", json.loads(messages[3]["content"]))
        self.assertIn("must never execute", str(messages))

    def test_failed_triages_and_no_compaction(self):
        verdict = call("send_verdict", {"verdict": "malicious", "reasoning": "Evidence"})
        cases = [
            ([response([verdict], "length")], "token_limit"),
            ([response([], "stop"), response([], "stop")], "protocol_error"),
            ([harness.TriageFailure("context_limit", "context full")], "context_limit"),
            ([response([call("list", {"page": 0})]), response([], "stop")], "protocol_error"),
            ([response([call("send_verdict", {"verdict": "maybe", "reasoning": ""})])]*2, "failed"),
        ]
        for responses, status in cases:
            with self.subTest(status=status):
                messages = []
                result = harness.triage(self.archive, "npm", FakeClient(responses), 1, messages)
                self.assertEqual(result["status"], status)
                self.assertEqual(messages[0]["content"], harness.SYSTEM)

    def test_reminder_then_verdict(self):
        messages = []
        client = FakeClient([
            response([], "stop"),
            response([call("send_verdict", {"verdict": "benign", "reasoning": "Evidence"})]),
        ])
        result = harness.triage(self.archive, "pypi", client, 3, messages)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(messages[3]["role"], "user")
        self.assertIn("send_verdict", messages[3]["content"])

    def test_turn_budget_forces_verdict_with_validation_retry(self):
        valid = response([call("send_verdict", {"verdict": "benign", "reasoning": "Limited evidence"})])
        invalid = response([call("send_verdict", {"verdict": "benign"})])
        for endings, status, flags in (([valid], "completed", [False, True]),
                                       ([invalid, valid], "completed", [False, True, True]),
                                       ([invalid, invalid], "failed", [False, True, True]),
                                       ([response([call("list", {"page": 0})])], "protocol_error", [False, True]),
                                       ([response([], "length")], "token_limit", [False, True]),
                                       ([harness.TriageFailure("context_limit", "full")], "context_limit", [False, True])):
            with self.subTest(status=status, flags=flags):
                client = FakeClient([response([call("list", {"page": 0})]), *endings])
                messages = []
                result = harness.triage(self.archive, "pypi", client, 1, messages)
                self.assertEqual(result["status"], status)
                self.assertEqual(client.forced, flags)
                self.assertIn("budget is exhausted", messages[4]["content"])
                if status == "completed":
                    self.assertTrue(result["forced_verdict"])
                    self.assertEqual(result["turns"], len(flags))
        client = FakeClient([invalid, invalid])
        result = harness.triage(self.archive, "pypi", client, 1, [])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(client.forced, [False, True])

    def test_verdict_validation_retry_and_failure_budget(self):
        invalids = [
            call("send_verdict", {"verdict": "benign"}),
            call("send_verdict", {"verdict": "unknown", "reasoning": "Evidence"}),
            call("send_verdict", {"verdict": "benign", "reasoning": " "}),
            call("send_verdict", {"verdict": "benign", "reasoning": "Evidence", "extra": 1}),
            call("send_verdict", []),
            {"id": "bad-json", "function": {"name": "send_verdict", "arguments": "{"}},
        ]
        valid = call("send_verdict", {"verdict": "benign", "reasoning": "Evidence"})
        for invalid in invalids:
            with self.subTest(invalid=invalid):
                messages = []
                result = harness.triage(self.archive, "pypi", FakeClient([
                    response([invalid]), response([valid])]), 3, messages)
                self.assertEqual(result["status"], "completed")
                error = json.loads(messages[3]["content"])
                self.assertEqual(error["remaining_attempts"], 1)
                self.assertIn("reasoning", error["instruction"])
        for responses in ([response([invalids[0]]), response([], "stop"), response([invalids[1]])],
                          [response([invalids[0], invalids[1], valid])]):
            messages = []
            result = harness.triage(self.archive, "pypi", FakeClient(responses), 5, messages)
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["validation_errors"], 2)
            self.assertEqual(json.loads(messages[-1]["content"])["remaining_attempts"], 0)
        self.assertIn("verdict must", result["error"])

    def test_metrics_separate_failures_and_ecosystems(self):
        rows = [
            {"ecosystem": "npm", "status": "completed", "label_true": truth, "verdict": pred}
            for truth, pred in [("malicious", "malicious"), ("benign", "malicious"),
                                ("malicious", "benign"), ("benign", "benign")]]
        rows += [{"ecosystem": "npm", "status": "context_limit", "label_true": "malicious"},
                 {"ecosystem": "pypi", "status": "completed", "label_true": "malicious", "verdict": "malicious"}]
        report = harness.metrics(rows)["ecosystems"]
        self.assertEqual(report["npm"]["precision"], 0.5)
        self.assertEqual(report["npm"]["recall"], 0.5)
        self.assertEqual(report["npm"]["f1"], 0.5)
        self.assertEqual(report["npm"]["coverage"], 0.8)
        self.assertEqual(report["npm"]["failed_by_true_label"]["malicious"], 1)
        self.assertEqual(report["pypi"]["f1"], 1.0)
        self.assertEqual(harness.metrics([])["ecosystems"]["npm"]["f1"], 0)

    def test_http_errors_and_full_800_release_cli(self):
        received = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                received.append(payload)
                if self.path == "/fail/chat/completions":
                    self.send_response(400)
                    body = {"error": {"code": "context_length_exceeded", "message": "Too long"}}
                elif not isinstance(payload.get("tool_choice"), str):
                    self.send_response(400)
                    body = {"error": "Invalid tool_choice type: 'object'. Supported string values: none, auto, required"}
                else:
                    self.send_response(200)
                    body = response([call("send_verdict", {"verdict": "malicious", "reasoning": "Mock evidence"})])
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(body).encode())

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        endpoint = f"http://127.0.0.1:{server.server_port}"
        with self.assertRaises(harness.TriageFailure) as caught:
            harness.Client(endpoint + "/fail", "test", "", 5, 100).complete([])
        self.assertEqual(caught.exception.status, "context_limit")
        harness.Client(endpoint + "/v1", "test", "", 5, 100).complete([], force_verdict=True)
        self.assertEqual(received[-1]["tool_choice"], "required")
        self.assertEqual([t["function"]["name"] for t in received[-1]["tools"]], ["send_verdict"])
        received.clear()
        (self.root / "packages").mkdir()
        (self.root / "results").mkdir()
        with (self.root / "results/manifest.csv").open("w", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(["folder_name", "ecosystem", "label_true"])
            for i in range(800):
                name = f"sample-{i}.whl"
                (self.root / "packages" / name).write_bytes(self.archive.read_bytes())
                writer.writerow([name, "py" if i < 400 else "js", "benign" if i % 2 else "malicious"])
        output = self.root / "run"
        process = subprocess.run([sys.executable, str(Path(harness.__file__)), str(self.root),
                                  "--endpoint", endpoint + "/v1", "--model", "mock", "--output", str(output)],
                                 capture_output=True, text=True, timeout=60)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(len(received), 800)
        self.assertTrue(all(len(p["messages"]) == 2 for p in received))
        self.assertTrue(all("label_true" not in json.dumps(p) for p in received))
        self.assertEqual(len(list((output / "chats").glob("*.json"))), 800)
        self.assertEqual(len((output / "results.jsonl").read_text().splitlines()), 800)
        report = json.loads((output / "metrics.json").read_text())
        for ecosystem in ("npm", "pypi"):
            self.assertEqual(report["ecosystems"][ecosystem]["completed"], 400)
            self.assertEqual(report["ecosystems"][ecosystem]["precision"], 0.5)
            self.assertEqual(report["ecosystems"][ecosystem]["recall"], 1)
            self.assertAlmostEqual(report["ecosystems"][ecosystem]["f1"], 2 / 3)

        received.clear()
        limited_output = self.root / "limited-run"
        # Unselected archives must not be required for a limited run.
        (self.root / "packages/sample-799.whl").unlink()
        process = subprocess.run([sys.executable, str(Path(harness.__file__)), str(self.root),
                                  "--endpoint", endpoint + "/v1", "--model", "mock",
                                  "--limit", "50", "--output", str(limited_output)],
                                 capture_output=True, text=True, timeout=60)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(len(received), 50)
        self.assertIn("[50/50]", process.stdout)
        results = [json.loads(line) for line in (limited_output / "results.jsonl").read_text().splitlines()]
        self.assertEqual([r["archive"] for r in results], [f"sample-{i}.whl" for i in range(50)])
        self.assertEqual(len(list((limited_output / "chats").glob("*.json"))), 50)
        report = json.loads((limited_output / "metrics.json").read_text())["ecosystems"]
        self.assertEqual(report["pypi"]["total"], 50)
        self.assertEqual(report["pypi"]["precision"], 0.5)
        self.assertEqual(report["pypi"]["recall"], 1.0)
        self.assertAlmostEqual(report["pypi"]["f1"], 2 / 3)
        self.assertEqual(report["npm"]["total"], 0)
        config = json.loads((limited_output / "config.json").read_text())
        self.assertEqual(config["limit"], 50)
        self.assertEqual(config["max_turns"], 10)
        self.assertEqual(config["selected_releases"], 50)
        for invalid in (0, -1):
            with self.assertRaises(ValueError):
                harness.load_manifest(self.root, invalid)

        received.clear()
        selection = self.root / "selected.txt"
        names = ["sample-402.whl", "sample-1.whl", "sample-0.whl", "sample-401.whl"]
        selection.write_text("\ufeff\n" + "\r\n".join(names) + "\r\n", encoding="utf-8")
        selected_output = self.root / "selected-run"
        process = subprocess.run([sys.executable, str(Path(harness.__file__)), str(self.root),
                                  "--endpoint", endpoint + "/v1", "--model", "mock",
                                  "--packages-file", str(selection), "--output", str(selected_output)],
                                 capture_output=True, text=True, timeout=60)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(len(received), 4)
        self.assertIn("[4/4]", process.stdout)
        results = [json.loads(line) for line in (selected_output / "results.jsonl").read_text().splitlines()]
        self.assertEqual([r["archive"] for r in results], names)
        config = json.loads((selected_output / "config.json").read_text())
        self.assertEqual(config["selected_archives"], names)
        self.assertEqual(config["packages_file"], str(selection.resolve()))
        report = json.loads((selected_output / "metrics.json").read_text())["ecosystems"]
        for ecosystem in ("npm", "pypi"):
            self.assertEqual(report[ecosystem]["total"], 2)
            self.assertEqual(report[ecosystem]["precision"], 0.5)
            self.assertEqual(report[ecosystem]["recall"], 1)
            self.assertAlmostEqual(report[ecosystem]["f1"], 2 / 3)
        with self.assertRaisesRegex(ValueError, "cannot be combined"):
            harness.load_manifest(self.root, limit=1, packages_file=selection)
        for content, error in (("\n", "empty"), ("sample-1.whl\nsample-1.whl", "duplicate"),
                               ("unknown.whl", "not found in manifest"),
                               ("../sample-1.whl", "not found in manifest"),
                               ("sample-799.whl", "Missing archive")):
            selection.write_text(content)
            with self.subTest(content=content), self.assertRaisesRegex(ValueError, error):
                harness.load_manifest(self.root, packages_file=selection)


if __name__ == "__main__":
    unittest.main()
