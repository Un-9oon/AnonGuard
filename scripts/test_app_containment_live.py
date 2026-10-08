"""Destructive namespace fixture for an explicitly designated disposable root CI host."""
import importlib.util
import os
from pathlib import Path
import shutil
import socket
import select
import subprocess
import tempfile
from unittest.mock import patch

if os.geteuid() != 0 or os.environ.get("ANONGUARD_DISPOSABLE_APP_TEST") != "1":
    raise SystemExit("Requires root and ANONGUARD_DISPOSABLE_APP_TEST=1 on disposable CI")
spec = importlib.util.spec_from_file_location("launcher", Path(__file__).with_name("anonguard_run_app.py"))
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)
namespace = f"ag-app-{os.getpid()}"
server = None
ip = shutil.which("ip")
with tempfile.TemporaryDirectory(prefix="anonguard-rootfs-", dir="/var/lib") as directory:
    root = Path(directory)
    root.chmod(0o755)
    (root / "app").mkdir()
    for name in ("proc", "dev", "tmp", "run"):
        (root / name).mkdir()
    source = Path(__file__).resolve().parent.parent / "tests/app_containment_probe.c"
    subprocess.run(["gcc", "-static", "-Wall", "-Wextra", "-Werror", str(source),
                    "-o", str(root / "app/probe")], check=True)
    with tempfile.TemporaryDirectory(prefix="anonguard-host-") as host_directory:
        sentinel = Path(host_directory) / "host-secret"
        sentinel.write_text("must not enter the sandbox")
        broker = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        broker.bind(str(Path(host_directory) / "broker.sock"))
        inherited = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        os.dup2(inherited.fileno(), 200, inheritable=True)
        try:
            subprocess.run([ip, "netns", "add", namespace], check=True)
            subprocess.run([ip, "-n", namespace, "link", "set", "lo", "up"], check=True)
            code = """import socket
s=socket.socket(); s.bind(('127.0.0.1',9050)); s.listen(); print('ready',flush=True)
while True:
 c,_=s.accept()
 with c: c.sendall(c.recv(4))
"""
            server = subprocess.Popen([ip, "netns", "exec", namespace, "/usr/bin/python3", "-c", code],
                                      stdout=subprocess.PIPE, text=True)
            assert select.select([server.stdout], [], [], 10)[0], "Proxy fixture readiness timed out"
            assert server.stdout.readline().strip() == "ready"
            command = ["/app/probe", str(sentinel), "open"]
            for _ in range(2):
                # Second launch verifies atomic rule replacement/repeated use.
                result = launcher.run(namespace, root, 9050, command, 65534, 65534)
                if result != 0:
                    # Diagnose a failed trusted fixture only; retain the original
                    # failure and never enable diagnostic output for real apps.
                    original_popen = subprocess.Popen
                    with tempfile.TemporaryFile() as diagnostics:
                        def diagnostic_popen(*args, **kwargs):
                            kwargs["stderr"] = diagnostics
                            argv = args[0]
                            if "/usr/bin/bwrap" in argv and shutil.which("strace"):
                                argv = ["strace", "-f", "-e",
                                        "trace=openat,write,prctl,clone,unshare,setresuid,setresgid",
                                        "-o", str(root / "setup-trace.log"), *argv]
                            return original_popen(argv, *args[1:], **kwargs)
                        with patch.object(launcher.subprocess, "Popen", side_effect=diagnostic_popen):
                            launcher.run(namespace, root, 9050, command, 65534, 65534)
                        diagnostics.seek(0)
                        print(diagnostics.read(8192).decode(errors="replace"), flush=True)
                        trace = root / "setup-trace.log"
                        if trace.exists():
                            lines = trace.read_text().splitlines()
                            important = [line for line in lines if any(word in line for word in
                                         ("uid_map", "gid_map", "EPERM", "EACCES", "DUMPABLE", "NO_NEW_PRIVS"))]
                            print("\n".join(important[:12] + important[-30:]), flush=True)
                    kernel = subprocess.run(["dmesg", "--color=never"], capture_output=True, text=True)
                    print("\n".join(line for line in kernel.stdout.splitlines()
                                    if "apparmor" in line.lower())[-12000:], flush=True)
                    for setting in ("apparmor_restrict_unprivileged_userns",
                                    "apparmor_restrict_unprivileged_unconfined"):
                        path = Path("/proc/sys/kernel") / setting
                        if path.exists():
                            print(setting, path.read_text().strip(), flush=True)
                assert result == 0, f"Sandbox probe failed, exit={result}"
            server.terminate()
            server.wait(timeout=5)
            result = launcher.run(namespace, root, 9050, ["/app/probe", str(sentinel), "closed"],
                                  65534, 65534)
            assert result == 0, f"Helper-death probe failed, exit={result}"
            print("Private filesystem, descriptors, UID/caps, syscall policy, proxy flow and helper-death checks passed")
        finally:
            if server is not None and server.poll() is None:
                server.kill()
                server.wait()
            os.close(200)
            inherited.close()
            broker.close()
            subprocess.run([ip, "netns", "delete", namespace], check=False)
