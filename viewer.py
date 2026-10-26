#!/usr/bin/env python3
"""Local read-only archive viewer. Python 3.11+, no dependencies."""
import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import urllib.parse

from harness import Archive, integer, load_manifest

ASSETS = Path(__file__).resolve().parent / "viewer"
STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/style.css": ("style.css", "text/css; charset=utf-8")}


class ViewerServer(HTTPServer):
    # Sequential requests deliberately serialize access to the archive handle.
    def __init__(self, address, root):
        self.root = Path(root)
        self.rows = load_manifest(self.root)
        self.archive = None
        self.archive_id = None
        super().__init__(address, Handler)

    def get_archive(self, package_id):
        integer(package_id, 1, len(self.rows))
        if package_id != self.archive_id:
            if self.archive:
                self.archive.close()
            self.archive, self.archive_id = None, None
            path = self.root / "packages" / self.rows[package_id - 1]["folder_name"]
            if path.is_symlink() or path.resolve().parent != (self.root / "packages").resolve():
                raise ValueError("Unsafe archive path")
            self.archive = Archive(path)
            self.archive_id = package_id
        return self.archive

    def server_close(self):
        if self.archive:
            self.archive.close()
        super().server_close()


class Handler(BaseHTTPRequestHandler):
    server_version = "OMCBViewer"

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, *args):
        # Do not print untrusted archive paths or contents to the terminal.
        pass

    def respond(self, status, body, content_type="application/json; charset=utf-8"):
        if not isinstance(body, bytes):
            body = json.dumps(body, ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; "
                         "style-src 'self'; connect-src 'self'; img-src 'none'; "
                         "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        host = self.headers.get("Host", "")
        port = self.server.server_port
        if host not in {f"127.0.0.1:{port}", f"localhost:{port}"}:
            return self.respond(403, {"error": "Only the local viewer host is allowed"})
        origin = self.headers.get("Origin")
        if (origin and origin != f"http://{host}") or self.headers.get("Sec-Fetch-Site") == "cross-site":
            return self.respond(403, {"error": "Cross-origin requests are forbidden"})
        url = urllib.parse.urlsplit(self.path)
        if url.path in STATIC:
            name, content_type = STATIC[url.path]
            return self.respond(200, (ASSETS / name).read_bytes(), content_type)
        if not url.path.startswith("/api/"):
            return self.respond(404, {"error": "Not found"})
        # Cross-origin JS cannot set this header without a successful CORS preflight.
        if self.headers.get("X-Archive-Viewer") != "1":
            return self.respond(403, {"error": "Viewer request header required"})
        try:
            params = urllib.parse.parse_qs(url.query, keep_blank_values=True, max_num_fields=10)
            if any(len(v) != 1 for v in params.values()):
                raise ValueError("Duplicate query parameters")
            def param(name, default=""):
                return params.get(name, [default])[0]
            if url.path == "/api/packages":
                return self.respond(200, {"packages": [
                    {"id": i, "name": row["folder_name"], "label_true": row["label_true"],
                     "ecosystem": {"py": "pypi", "js": "npm"}[row["ecosystem"]]}
                    for i, row in enumerate(self.server.rows, 1)]})
            if url.path not in ("/api/list", "/api/read"):
                return self.respond(404, {"error": "Unknown API route"})
            archive = self.server.get_archive(int(param("id")))
            if url.path == "/api/read":
                return self.respond(200, archive.read(param("path"), int(param("offset", "0")), 16384))
            page = integer(int(param("page", "0")), 0, 1_000_000)
            query = param("q")
            if query:
                entries = [{"path": p, "type": "file", "size": v[1]}
                           for p, v in sorted(archive.files.items()) if query.casefold() in p.casefold()]
                start = page * 100
                listing = {"entries": entries[start:start + 100], "total": len(entries),
                           "page": page, "next_page": page + 1 if start + 100 < len(entries) else None}
            else:
                listing = archive.listing(param("path"), page)
            return self.respond(200, listing)
        except (ValueError, KeyError, OSError) as exc:
            return self.respond(400, {"error": str(exc)})
        except Exception:
            return self.respond(400, {"error": "Cannot read this archive; unsupported or damaged content"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("benchmark", type=Path, help="Path to open-malicious-code-benchmark")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535")
    try:
        server = ViewerServer(("127.0.0.1", args.port), args.benchmark)
    except (OSError, ValueError, KeyError) as exc:
        parser.error(str(exc))
    print(f"Archive viewer: http://127.0.0.1:{server.server_port} (Ctrl+C to stop)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
