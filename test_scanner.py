"""Unit tests for scanner helpers that run without network access."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import scanner


class ParsePortsTests(unittest.TestCase):
    def test_single_port(self):
        self.assertEqual(scanner.parse_ports("80"), [80])

    def test_comma_separated(self):
        self.assertEqual(scanner.parse_ports("80,443,22"), [22, 80, 443])

    def test_range(self):
        self.assertEqual(scanner.parse_ports("20-25"), [20, 21, 22, 23, 24, 25])

    def test_mixed(self):
        self.assertEqual(scanner.parse_ports("22,80,100-102"), [22, 80, 100, 101, 102])

    def test_duplicates_removed(self):
        self.assertEqual(scanner.parse_ports("80,80,80"), [80])

    def test_invalid_port_rejected(self):
        with self.assertRaises(ValueError):
            scanner.parse_ports("70000")

    def test_reversed_range_rejected(self):
        with self.assertRaises(ValueError):
            scanner.parse_ports("100-20")

    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            scanner.parse_ports("")


class TcpScanTests(unittest.TestCase):
    def test_closed_port_on_localhost(self):
        # Port 1 is almost certainly closed; the probe must not raise.
        result = scanner.tcp_scan("127.0.0.1", [1], timeout=0.5)
        self.assertEqual(len(result.ports), 1)
        self.assertFalse(result.ports[0].open)

    def test_open_port_detected(self):
        import socket as pysocket
        import threading

        server = pysocket.socket(pysocket.AF_INET, pysocket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        thread = threading.Thread(target=server.accept, daemon=True)
        thread.start()
        try:
            result = scanner.tcp_scan("127.0.0.1", [port], timeout=1.0)
            self.assertTrue(result.ports[0].open)
        finally:
            server.close()


if __name__ == "__main__":
    unittest.main()


class ServiceDetectionTests(unittest.TestCase):
    def test_passive_banner_grab(self):
        import socket as pysocket
        import threading

        import probes

        server = pysocket.socket(pysocket.AF_INET, pysocket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def serve():
            conn, _ = server.accept()
            conn.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")
            conn.close()

        threading.Thread(target=serve, daemon=True).start()
        try:
            banner = probes.passive_banner("127.0.0.1", port, timeout=2.0)
            self.assertIn("SSH-2.0", banner)
            self.assertEqual(probes._guess_protocol(banner, port), "ssh")
        finally:
            server.close()

    def test_http_probe_extracts_title_and_links(self):
        import http.server
        import threading

        import probes

        class Handler(http.server.BaseHTTPRequestHandler):
            server_version = "TestServer/1.0"
            sys_version = ""

            def do_GET(self):
                body = (b"<html><head><title>Test Page</title></head>"
                        b"<body><a href='/a'>a</a><a href='/b'>b</a>"
                        b"<a href='/a'>dup</a></body></html>")
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            info = probes.http_probe("127.0.0.1", port, timeout=2.0, use_tls=False)
            self.assertIsNotNone(info)
            self.assertEqual(info.title, "Test Page")
            self.assertEqual(info.server, "TestServer/1.0")
            self.assertEqual(info.links, ["/a", "/b"])
            self.assertEqual(info.url, f"http://127.0.0.1:{port}/")
        finally:
            httpd.shutdown()
