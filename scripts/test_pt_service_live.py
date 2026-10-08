#!/usr/bin/env python3
"""Disposable Linux VM only: installed PT units, credentials, restart and crash isolation."""
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import time
import uuid


def run(*args):
    result = subprocess.run(args, capture_output=True, timeout=30, check=False)
    if result.returncode:
        raise RuntimeError(f"{args[0]} {args[1]} failed (exit {result.returncode})")
    return result.stdout.decode().strip()


def main():
    if os.geteuid() != 0 or os.environ.get("ANONGUARD_DISPOSABLE_PT_TEST") != "1":
        raise RuntimeError("requires root and ANONGUARD_DISPOSABLE_PT_TEST=1 on a disposable Linux VM")
    source = Path(os.environ.get("ANONGUARD_OBFS4PROXY", "/usr/bin/obfs4proxy")).resolve(strict=True)
    suffix = uuid.uuid4().hex
    server_name = "test-server-" + suffix
    client_name = "test-client-" + suffix
    services = [f"anonguard-pt@{server_name}.service", f"anonguard-pt@{client_name}.service",
                f"anonguard-pt-probe-{suffix}.service"]
    binary = Path("/usr/local/bin") / ("anonguard-pt-test-" + suffix)
    probe = Path("/usr/local/bin") / ("anonguard-pt-probe-" + suffix + ".py")
    unit = Path("/run/systemd/system") / services[2]
    configs = [Path("/etc/anonguard") / ("pt-" + name + ".json") for name in (server_name, client_name)]
    runtimes = [Path("/run") / ("anonguard-pt-" + name) for name in (server_name, client_name)]
    states = [Path("/var/lib/private") / ("anonguard-pt-" + name) for name in (server_name, client_name)]
    for path in [binary, probe, unit, *configs, *runtimes, *states]:
        if path.exists() or path.is_symlink():
            raise RuntimeError("test path unexpectedly exists")
    try:
        shutil.copyfile(source, binary)
        binary.chmod(0o755)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        configs[0].write_text(json.dumps({"mode": "server", "binary": str(binary),
            "listen": f"127.0.0.1:{port}", "backend": "127.0.0.1:39999"}))
        configs[0].chmod(0o600)
        run("systemd-analyze", "verify", "/lib/systemd/system/anonguard-pt@.service")
        run("systemctl", "start", services[0])
        server = json.loads((runtimes[0] / "server.json").read_text())
        run("systemctl", "restart", services[0])
        assert json.loads((runtimes[0] / "server.json").read_text()) == server, "server identity changed on restart"
        binding = {"identity": list(bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")),
                   "bridge": server["listen"], "arguments": server["arguments"]}
        configs[1].write_text(json.dumps({"mode": "client", "binary": str(binary),
                                       "bridges": [binding], "authorities": [binding]}))
        configs[1].chmod(0o600)
        run("systemctl", "start", services[1])
        for name in ("bridges.json", "authorities.json"):
            assert (runtimes[1] / name).stat().st_mode & 0o777 == 0o600
        probe.write_text("import json, os\nfrom pathlib import Path\n"
                         "for name in ('bridges.json','authorities.json'):\n"
                         " p=Path(os.environ['CREDENTIALS_DIRECTORY'])/name\n"
                         " info=p.stat()\n"
                         " assert not info.st_mode & 0o027\n"
                         " assert info.st_uid in (0,os.getuid())\n"
                         " assert not info.st_mode & 0o040 or info.st_gid in (0,os.getgid())\n"
                         " assert json.loads(p.read_text())[0]['proxy'].startswith('127.0.0.1:')\n")
        probe.chmod(0o755)
        unit.write_text(f"[Unit]\nRequires={services[1]}\nAfter={services[1]}\nBindsTo={services[1]}\n"
                        "[Service]\nType=oneshot\nRemainAfterExit=yes\nDynamicUser=yes\n"
                        f"LoadCredential=bridges.json:{runtimes[1]}/bridges.json\n"
                        f"LoadCredential=authorities.json:{runtimes[1]}/authorities.json\n"
                        f"ExecStart=/usr/bin/python3 {probe}\n")
        run("systemctl", "daemon-reload")
        run("systemctl", "start", services[2])
        assert run("systemctl", "is-active", services[2]) == "active"
        supervisor_pid = int(run("systemctl", "show", "--property=MainPID", "--value", services[1]))
        children = Path(f"/proc/{supervisor_pid}/task/{supervisor_pid}/children").read_text().split()
        assert len(children) == 1
        os.kill(int(children[0]), signal.SIGKILL)
        deadline = time.monotonic() + 4
        while (runtimes[1] / "bridges.json").exists():
            assert time.monotonic() < deadline, "stale client readiness survived PT crash"
            time.sleep(0.05)
        assert not (runtimes[1] / "authorities.json").exists()
        # BindsTo must stop a dependent service when its transport disappears.
        deadline = time.monotonic() + 4
        while subprocess.run(["systemctl", "is-active", "--quiet", services[2]], check=False).returncode == 0:
            assert time.monotonic() < deadline, "dependent service survived PT failure"
            time.sleep(0.05)
        print("PASS: installed PT units, private DynamicUser credentials, persisted server identity, crash cleanup and dependent stop")
        print("Scope: service lifecycle; backend anonymity/circuit behavior is covered by separate real testnet tests")
    finally:
        for service in reversed(services):
            subprocess.run(["systemctl", "stop", service], capture_output=True, timeout=20, check=False)
            subprocess.run(["systemctl", "reset-failed", service], capture_output=True, timeout=10, check=False)
        for path in [unit, *configs, binary, probe]:
            path.unlink(missing_ok=True)
        run("systemctl", "daemon-reload")
        for name, state in zip((server_name, client_name), states):
            link = Path("/var/lib") / ("anonguard-pt-" + name)
            if link.is_symlink():
                link.unlink()
            if state.exists():
                shutil.rmtree(state)


if __name__ == "__main__":
    main()
