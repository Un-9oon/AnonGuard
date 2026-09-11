"""
research_benchmarks.leak_audit
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Empirical zero-leak evaluation suite.
Tests socket failure transitions and verifies fail-closed guarantees.
"""

import sys
import unittest
from anonguard.sdk import AnonGuard, GuardConfig, KillSwitchTrippedError


class LeakAuditTest(unittest.TestCase):
    """Verifies that no unencrypted/unproxied traffic leaks during link failure."""

    def test_killswitch_prevents_unproxied_fallback(self):
        """Simulates proxy crash and asserts that requests fail immediately."""
        guard = AnonGuard(proxies=["socks5h://127.0.0.1:9999"], config=GuardConfig(strict_killswitch=True))
        session = guard.get_guarded_session()

        with self.assertRaises(KillSwitchTrippedError) as ctx:
            session.get("http://example.com", timeout=2.0)

        self.assertIn("KillSwitch", str(ctx.exception))
        self.assertTrue(guard.is_kill_switch_tripped())

    def test_ipv6_fallback_blocked(self):
        """Verifies that IPv6 address family lookups are intercepted and blocked."""
        guard = AnonGuard(config=GuardConfig(disable_ipv6=True))
        import socket
        with self.assertRaises(socket.gaierror):
            socket.getaddrinfo("example.com", 80, socket.AF_INET6)


if __name__ == "__main__":
    print("[*] Running AnonGuard Empirical Zero-Leak Audit...")
    unittest.main()
