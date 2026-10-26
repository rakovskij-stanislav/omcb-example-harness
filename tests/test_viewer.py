import http.client
import io
import json
from pathlib import Path
import tarfile
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import urlencode
import zipfile

import viewer


class ViewerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'packages').mkdir()
        self.payload = '<script>fetch("https://attacker.invalid")</script><img src=x onerror=alert(1)>'
        with zipfile.ZipFile(self.root / 'packages/sample.whl', 'w') as z:
            z.writestr('pkg/index.html', self.payload)
            z.writestr('pkg/code.py', 'raise RuntimeError("never execute")')
            z.writestr('pkg/large.js', 'x' * 17000)
            z.writestr('pkg/binary', b'\xff\x00\x01')
            for i in range(101):
                z.writestr(f'many/{i:03}.txt', 'text')
        with tarfile.open(self.root / 'packages/links.tgz', 'w:gz') as tar:
            member = tarfile.TarInfo('package/link')
            member.type = tarfile.SYMTYPE
            member.linkname = '/etc/passwd'
            tar.addfile(member)
            member = tarfile.TarInfo('package/index.js')
            member.size = 4
            tar.addfile(member, io.BytesIO(b'text'))
        (self.root / 'packages/bad.zip').write_bytes(b'not an archive')
        rows = [{'folder_name': name, 'ecosystem': eco, 'label_true': 'benign' if eco == 'py' else 'malicious'}
                for name, eco in [('sample.whl', 'py'), ('links.tgz', 'js'), ('bad.zip', 'js')]]
        with patch('viewer.load_manifest', return_value=rows):
            self.server = viewer.ViewerServer(('127.0.0.1', 0), self.root)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def get(self, route, params=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        try:
            connection.request('GET', route + ('?' + urlencode(params) if params else ''),
                               headers={'X-Archive-Viewer': '1', **(headers or {})})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def api(self, route, params=None):
        status, headers, body = self.get('/api/' + route, params)
        return status, json.loads(body)

    def test_ui_assets_and_security_headers(self):
        for route in ('/', '/app.js', '/style.css'):
            status, headers, body = self.get(route)
            self.assertEqual(status, 200)
            self.assertTrue(body)
            self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')
            self.assertEqual(headers['Cache-Control'], 'no-store')
            self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
        for route in ('/packages/sample.whl', '/harness.py', '/../harness.py', '/%2e%2e/harness.py'):
            self.assertEqual(self.get(route)[0], 404)

    def test_package_catalog_includes_benchmark_labels(self):
        status, data = self.api('packages')
        self.assertEqual(status, 200)
        self.assertEqual(data['packages'][0]['ecosystem'], 'pypi')
        self.assertEqual(data['packages'][0]['label_true'], 'benign')
        self.assertEqual(data['packages'][1]['label_true'], 'malicious')

    def test_listing_search_and_symlink_shadowing(self):
        status, data = self.api('list', {'id': 1, 'path': 'many'})
        self.assertEqual(status, 200)
        self.assertEqual(len(data['entries']), 100)
        self.assertEqual(data['next_page'], 1)
        _, data = self.api('list', {'id': 1, 'path': 'many', 'page': 1})
        self.assertEqual(len(data['entries']), 1)
        _, data = self.api('list', {'id': 1, 'q': 'CODE.PY'})
        self.assertEqual(data['entries'][0]['path'], 'pkg/code.py')
        _, data = self.api('list', {'id': 2, 'path': 'package'})
        self.assertEqual([e['path'] for e in data['entries']], ['package/index.js'])
        self.assertEqual(self.api('read', {'id': 2, 'path': 'package/link'})[0], 400)

    def test_content_is_json_not_active_html_and_chunked(self):
        status, headers, body = self.get('/api/read', {'id': 1, 'path': 'pkg/index.html'})
        self.assertEqual(status, 200)
        self.assertTrue(headers['Content-Type'].startswith('application/json'))
        self.assertEqual(json.loads(body)['text'], self.payload)
        _, data = self.api('read', {'id': 1, 'path': 'pkg/large.js'})
        self.assertEqual(data['bytes_read'], 16384)
        self.assertFalse(data['eof'])
        _, data = self.api('read', {'id': 1, 'path': 'pkg/large.js', 'offset': 16384})
        self.assertEqual(data['bytes_read'], 616)
        self.assertTrue(data['eof'])
        _, data = self.api('read', {'id': 1, 'path': 'pkg/binary'})
        self.assertEqual(data['base64'], '/wAB')
        self.assertFalse((self.root / 'pkg').exists())

    def test_invalid_paths_ids_and_archives(self):
        for params in ({'id': 0}, {'id': 999}, {'id': '../sample.whl'}, {'id': 1, 'path': '../etc/passwd'},
                       {'id': 1, 'path': '/etc/passwd'}, {'id': 1, 'path': 'pkg/code.py', 'offset': -1}):
            self.assertEqual(self.api('read', params)[0], 400)
        self.assertEqual(self.api('list', {'id': 3})[0], 400)
        self.assertEqual(self.api('list', {'id': 1})[0], 200)
        self.assertEqual(self.get('/api/list?id=1&id=2')[0], 400)

    def test_host_origin_and_api_header_guards(self):
        for headers in ({'Host': 'attacker.invalid'}, {'Origin': 'https://attacker.invalid'},
                        {'Sec-Fetch-Site': 'cross-site'}, {'X-Archive-Viewer': ''}):
            self.assertEqual(self.get('/api/packages', headers=headers)[0], 403)
        headers = {'Origin': f'http://127.0.0.1:{self.server.server_port}'}
        self.assertEqual(self.get('/api/packages', headers=headers)[0], 200)


if __name__ == '__main__':
    unittest.main()
