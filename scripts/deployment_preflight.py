#!/usr/bin/python3 -I
"""Read-only prerequisites inventory; never a substitute for live isolation tests."""
import argparse
import ctypes
import json
from pathlib import Path
import platform
import shutil
import sys


def inventory(profile):
    checks = []

    def record(name, passed, detail):
        checks.append({"name": name, "passed": bool(passed), "detail": detail})

    record("linux", sys.platform == "linux", platform.system())
    record("cgroup_v2", Path("/sys/fs/cgroup/cgroup.controllers").is_file(),
           "Required for the documented systemd resource profile")
    commands = ["anonguard-daemon", "systemctl", "timedatectl"]
    if profile == "headless":
        commands += ["anonguard-run-app", "ip", "nft", "bwrap", "setpriv"]
        record("native_abi", platform.machine() in ("x86_64", "aarch64"),
               "Headless syscall policy supports native x86_64/aarch64 only")
        try:
            ctypes.CDLL("libseccomp.so.2")
            available = True
        except OSError:
            available = False
        record("libseccomp", available, "Required by the headless launcher")
    for command in commands:
        location = shutil.which(command)
        record(command, location is not None, location or "Not found in PATH")
    return {
        "profile": profile,
        "prerequisites_present": all(check["passed"] for check in checks),
        "deployment_accepted": False,
        "checks": checks,
        "manual_checks": [
            "Verify signed artifact origin or explicitly record an unsigned local build",
            "Authenticate authority endpoints and public keys out of band",
            "Check time synchronization, dedicated identities and persistent state",
            "Measure service resource limits under the intended workload",
            "Run deployment acceptance and live failure/leak tests on this kernel",
        ] + ([
            "Validate the dedicated rootfs and application UID/GID using the launcher",
            "Review executable-specific AppArmor policy; do not disable host restrictions",
            "Apply cgroup budgets to the separately launched protected application",
        ] if profile == "headless" else []),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("gateway", "headless"), default="gateway")
    args = parser.parse_args()
    result = inventory(args.profile)
    print(json.dumps(result, indent=2))
    return 0 if result["prerequisites_present"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
