"""Real HTTP trials and broken-proxy refusal, using owned loopback fixtures."""
import http.server
import importlib.util
from pathlib import Path
import shutil
import socket
import threading
import unittest

spec = importlib.util.spec_from_file_location('latency_profile', Path(__file__).with_name('latency_profile.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'evaluation payload'
        self.send_response(200 if self.path == '/ok' else 503)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@unittest.skipUnless(shutil.which('curl'), 'curl required')
class MeasurementTests(unittest.TestCase):
    def setUp(self):
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f'http://127.0.0.1:{self.server.server_port}'

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def test_http_and_failure_accounting(self):
        samples = [module.measure(shutil.which('curl'), self.url + p, None, 1) for p in ('/ok', '/failure')]
        report = module.summarize(samples, 1)
        self.assertEqual((report['successes'], report['failures']), (1, 1))
        self.assertEqual(report['successful_download_bytes'], len(b'evaluation payload'))
        self.assertEqual(samples[1]['http_status'], 503)

    def test_failed_proxy_never_uses_direct_destination(self):
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            proxy = f'socks5h://127.0.0.1:{reserved.getsockname()[1]}'
            sample = module.measure(shutil.which('curl'), self.url + '/ok', proxy, 1)
        self.assertFalse(sample['success'])
        self.assertEqual(sample['downloaded_bytes'], 0)
        report = module.summarize([sample], 1)
        self.assertEqual(report['failures'], 1)
        self.assertIsNone(report['latency_seconds_successful_only']['95'])


if __name__ == '__main__':
    unittest.main()
