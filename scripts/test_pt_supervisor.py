#!/usr/bin/env python3
"""Lifecycle regression tests, with opt-in real obfs4 process verification."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPT = Path(__file__).with_name("pt_supervisor.py")
spec = importlib.util.spec_from_file_location("pt_supervisor", SCRIPT)
pt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pt)


class SupervisorTests(unittest.TestCase):
    def test_endpoint_and_binding_validation(self):
        for endpoint in ["hostname:1", "[::1:1", "::1:1", "127.0.0.1:0", "127.0.0.1:65536"]:
            with self.assertRaises(ValueError):
                pt.address(endpoint)
        self.assertEqual(pt.address("[::1]:9001", loopback=True), "[::1]:9001")
        with self.assertRaises(ValueError):
            pt.address("192.0.2.1:9001", loopback=True)
        for values in [[], [{}], [{"identity": [0] * 32, "bridge": "127.0.0.1:1", "arguments": {"cert": "x"}}]]:
            with self.assertRaises(ValueError):
                pt.bindings(values, 3)

    def test_failed_startup_removes_stale_readiness_without_logging_certificates(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            binary = root / "obfs4proxy"
            binary.write_text("#!/usr/bin/python3\nprint('VERSION 1')\nprint('CMETHOD-ERROR obfs4 secret-certificate')\n")
            binary.chmod(0o700)
            runtime = root / "run"
            runtime.mkdir(mode=0o700)
            (runtime / "bridges.json").write_text("stale")
            binding = {"identity": [1] * 32, "bridge": "127.0.0.1:443", "arguments": {"cert": "x"}}
            config = root / "config.json"
            config.write_text(json.dumps({"mode": "client", "binary": str(binary), "bridges": [binding], "authorities": [binding]}))
            result = subprocess.run([sys.executable, str(SCRIPT), "--config", str(config),
                                     "--state", str(root / "state"), "--runtime", str(runtime)],
                                    capture_output=True, timeout=5, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(b"secret-certificate", result.stderr + result.stdout)
            self.assertFalse((runtime / "bridges.json").exists())

    @unittest.skipUnless(os.environ.get("ANONGUARD_OBFS4PROXY") and sys.platform == "linux", "requires real obfs4 and Linux process inspection")
    def test_real_transport_readiness_shutdown_and_crash_cleanup(self):
        binary = str(Path(os.environ["ANONGUARD_OBFS4PROXY"]).resolve(strict=True))
        processes = []
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            def start(name, data):
                config = root / (name + ".json")
                config.write_text(json.dumps(dict(data, binary=binary)))
                runtime = root / (name + "-run")
                process = subprocess.Popen([sys.executable, str(SCRIPT), "--config", str(config),
                                            "--state", str(root / (name + "-state")), "--runtime", str(runtime)],
                                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                           env={k: v for k, v in os.environ.items() if k != "NOTIFY_SOCKET"})
                processes.append(process)
                return process, runtime

            def read_ready(process, path):
                deadline = time.monotonic() + 10
                while not path.exists():
                    self.assertIsNone(process.poll(), "supervisor exited before readiness")
                    self.assertLess(time.monotonic(), deadline, "readiness timeout")
                    time.sleep(0.02)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                return json.loads(path.read_text())

            try:
                with socket.socket() as reservation, socket.socket() as backend:
                    reservation.bind(("127.0.0.1", 0))
                    port = reservation.getsockname()[1]
                    backend.bind(("127.0.0.1", 0))
                    backend.listen()
                    reservation.close()
                    server, server_run = start("server", {"mode": "server", "listen": f"127.0.0.1:{port}",
                                                          "backend": f"127.0.0.1:{backend.getsockname()[1]}"})
                    method = read_ready(server, server_run / "server.json")
                    binding = {"identity": list(bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")),
                               "bridge": method["listen"], "arguments": method["arguments"]}
                    client, client_run = start("client", {"mode": "client", "bridges": [binding], "authorities": [binding]})
                    entries = read_ready(client, client_run / "bridges.json")
                    authorities = read_ready(client, client_run / "authorities.json")
                    self.assertEqual(entries, authorities)
                    host, port = entries[0]["proxy"].rsplit(":", 1)
                    with socket.create_connection((host, int(port)), timeout=2) as probe:
                        probe.sendall(bytes([5, 1, 2]))
                        self.assertEqual(probe.recv(2), bytes([5, 2]))
                    child_ids = Path(f"/proc/{client.pid}/task/{client.pid}/children").read_text().split()
                    self.assertEqual(len(child_ids), 1)
                    os.kill(int(child_ids[0]), signal.SIGKILL)
                    self.assertEqual(client.wait(timeout=5), 1)
                    self.assertFalse((client_run / "bridges.json").exists())
                    self.assertFalse((client_run / "authorities.json").exists())
                    server.terminate()
                    self.assertEqual(server.wait(timeout=5), 0)
                    self.assertFalse((server_run / "server.json").exists())
            finally:
                for process in processes:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=5)
                    if process.stderr:
                        process.stderr.close()


if __name__ == "__main__":
    unittest.main()
