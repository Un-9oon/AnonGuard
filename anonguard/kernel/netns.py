"""
anonguard.kernel.netns
~~~~~~~~~~~~~~~~~~~~~~
Linux Network Namespace and nftables isolation primitives.
"""

import shutil
import subprocess
from typing import Dict, List, Optional


class LinuxNetnsGuard:
    """Provides helpers and script templates for kernel-level network namespace sandboxing."""

    @staticmethod
    def is_netns_supported() -> bool:
        """Checks if iproute2 and netns are available on the Linux host."""
        return shutil.which("ip") is not None

    @staticmethod
    def generate_isolation_script(namespace: str = "anonguard_ns", proxy_ip: str = "127.0.0.1") -> str:
        """Generates a bash script to set up a zero-leak network namespace with strict nftables/iptables."""
        return f"""#!/usr/bin/env bash
# AnonGuard Kernel Isolation Script
set -euo pipefail

NS="{namespace}"
PROXY_IP="{proxy_ip}"

echo "[*] Creating network namespace: $NS"
ip netns add "$NS" || true

echo "[*] Configuring loopback..."
ip -n "$NS" link set lo up

echo "[*] Applying fail-closed firewall inside namespace..."
# Drop everything except traffic destined for the authorized proxy endpoint
ip netns exec "$NS" iptables -P OUTPUT DROP
ip netns exec "$NS" iptables -A OUTPUT -o lo -j ACCEPT
ip netns exec "$NS" iptables -A OUTPUT -d "$PROXY_IP" -j ACCEPT

echo "[+] Namespace $NS is now strictly isolated (fail-closed)."
echo "Run any command inside: ip netns exec $NS <command>"
"""
