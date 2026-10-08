import importlib.util
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("launcher", Path(__file__).with_name("anonguard_run_app.py"))
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


class LauncherContract(unittest.TestCase):
    def test_filter_enforces_families_in_disposable_child(self):
        code = r'''
import ctypes, importlib.util, os, socket, tempfile
spec = importlib.util.spec_from_file_location("launcher", os.environ["LAUNCHER_SOURCE"])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
# Establish that pathname IPC sockets work before this policy is loaded.
socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).close()
with tempfile.TemporaryFile() as f:
 m.export_filter(f.fileno()); data = f.read()
 buf = ctypes.create_string_buffer(data)
 class Program(ctypes.Structure):
  _fields_ = [("length", ctypes.c_ushort), ("filter", ctypes.c_void_p)]
 program = Program(len(data)//8, ctypes.addressof(buf))
 libc = ctypes.CDLL(None, use_errno=True)
 assert libc.prctl(38, 1, 0, 0, 0) == 0
 assert libc.prctl(22, 2, ctypes.byref(program), 0, 0) == 0
 for family in (socket.AF_UNIX, socket.AF_NETLINK, socket.AF_PACKET):
  try: socket.socket(family, socket.SOCK_STREAM)
  except PermissionError: pass
  else: raise AssertionError(f"family {family} admitted")
 socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()
 socket.socket(socket.AF_INET6, socket.SOCK_STREAM).close()
'''
        import os
        environment = dict(os.environ, LAUNCHER_SOURCE=str(Path(launcher.__file__).resolve()))
        subprocess.run([sys.executable, "-c", code], env=environment, check=True, timeout=10)

    def test_native_filter_exports_real_bpf(self):
        with tempfile.TemporaryFile() as policy:
            launcher.export_filter(policy.fileno())
            data = policy.read()
            self.assertGreater(len(data), 8)
            self.assertEqual(len(data) % 8, 0)

    def test_missing_or_untrusted_rootfs_is_rejected(self):
        with self.assertRaises(ValueError):
            launcher.validate_rootfs("/")
        with self.assertRaises(FileNotFoundError):
            launcher.validate_rootfs("/no-anonguard-rootfs-here")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                launcher.validate_rootfs(directory)

    def test_no_host_bind_or_user_option_passthrough(self):
        arguments = launcher.sandbox_arguments(Path("/var/lib/application-rootfs"), 7,
                                                ["/app/task", "--bind", "/", "/"])
        self.assertEqual(arguments[arguments.index("--") + 1:],
                         ["/app/task", "--bind", "/", "/"])
        self.assertEqual(arguments.count("--ro-bind"), 1)
        self.assertIn("--disable-userns", arguments)
        self.assertIn("--seccomp", arguments)
        self.assertNotIn("--unshare-net", arguments)
        with self.assertRaises(ValueError):
            launcher.sandbox_arguments(Path("/rootfs"), 7, ["--bind", "/"])

    def test_unprivileged_execution_refuses_before_setup(self):
        with patch.object(launcher.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(ValueError, "administrator"):
                launcher.run("anonguard", "/rootfs", 9050, ["/app/task"], 65534, 65534)


if __name__ == "__main__":
    unittest.main()
