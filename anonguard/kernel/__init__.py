"""
anonguard.kernel
~~~~~~~~~~~~~~~~
Zero-leak network and transport isolation primitives.
"""

from anonguard.kernel.killswitch import GuardedHTTPAdapter, KillSwitchSession
from anonguard.kernel.dns_shield import DNSShield
from anonguard.kernel.ipv6_blocker import IPv6Blocker
from anonguard.kernel.netns import LinuxNetnsGuard

__all__ = [
    "GuardedHTTPAdapter",
    "KillSwitchSession",
    "DNSShield",
    "IPv6Blocker",
    "LinuxNetnsGuard",
]
