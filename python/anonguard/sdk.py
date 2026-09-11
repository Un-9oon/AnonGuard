"""
anonguard.sdk
~~~~~~~~~~~~~
High-level Python SDK connecting application code (security scanners,
penetration testing agents, and automated tools)
to the AnonGuard zero-leak anonymity engine.
"""

from dataclasses import dataclass, field
import socket
import threading
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlunparse

import requests
from requests.adapters import HTTPAdapter


class KillSwitchTrippedError(Exception):
    """Raised when traffic is blocked because the kill switch is active."""
    pass


class AnonymityVerificationError(Exception):
    """Raised when pre-flight IP leak checks fail."""
    pass


@dataclass
class GuardConfig:
    """Operational policies for AnonGuard."""
    strict_killswitch: bool = True
    enforce_remote_dns: bool = True
    disable_ipv6: bool = True
    verify_ip_before_start: bool = True
    enable_jitter: bool = False
    min_chain_length: int = 1
    max_chain_length: int = 3
    verification_endpoints: List[str] = field(
        default_factory=lambda: [
            "https://api.ipify.org?format=json",
            "https://httpbin.org/ip",
            "https://ifconfig.me/ip",
            "https://icanhazip.com",
        ]
    )
    verification_timeout: float = 8.0


class GuardedHTTPAdapter(HTTPAdapter):
    """Adapter that intercepts every request and enforces fail-closed kill switch."""

    def __init__(self, guard: "AnonGuard", *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.guard = guard

    def send(self, request: Any, *args: Any, **kwargs: Any) -> Any:
        if self.guard.is_kill_switch_tripped():
            raise KillSwitchTrippedError(
                "[AnonGuard KillSwitch] Outbound transit blocked: Kill switch is active!"
            )

        try:
            return super().send(request, *args, **kwargs)
        except Exception as exc:
            err_msg = str(exc).lower()
            if any(term in err_msg for term in ["proxyerror", "socks", "connection refused", "tunnel"]):
                self.guard.trip_kill_switch(f"Upstream proxy failed: {exc}")
                raise KillSwitchTrippedError(
                    f"[AnonGuard KillSwitch] Upstream proxy failed! KillSwitch tripped to prevent leak. Error: {exc}"
                ) from exc
            raise


class AnonGuard:
    """The central orchestrator for AnonGuard Python integration."""

    def __init__(
        self,
        proxies: Optional[List[str]] = None,
        config: Optional[GuardConfig] = None,
        daemon_addr: str = "127.0.0.1:9050",
    ):
        self.config = config or GuardConfig()
        self.daemon_addr = daemon_addr
        self.proxies: List[str] = []
        self._kill_switch_tripped = False
        self._lock = threading.Lock()
        self._orig_getaddrinfo: Optional[Any] = None

        if proxies:
            for p in proxies:
                self.add_proxy(p)

        if self.config.disable_ipv6:
            self._disable_ipv6()

    def add_proxy(self, raw_url: str) -> None:
        """Adds a proxy URL, auto-upgrading socks5 to socks5h for remote DNS."""
        url = raw_url.strip()
        if self.config.enforce_remote_dns:
            parsed = urlparse(url)
            if parsed.scheme.lower() == "socks5":
                url = urlunparse(parsed._replace(scheme="socks5h"))
            elif parsed.scheme.lower() == "socks4":
                url = urlunparse(parsed._replace(scheme="socks4a"))
        with self._lock:
            self.proxies.append(url)

    def is_kill_switch_tripped(self) -> bool:
        with self._lock:
            return self._kill_switch_tripped

    def trip_kill_switch(self, reason: str = "") -> None:
        with self._lock:
            self._kill_switch_tripped = True

    def reset_kill_switch(self) -> None:
        with self._lock:
            self._kill_switch_tripped = False

    def _disable_ipv6(self) -> None:
        """Filters out AF_INET6 to prevent dual-stack IPv6 fallback leaks."""
        if self._orig_getaddrinfo is not None:
            return
        self._orig_getaddrinfo = socket.getaddrinfo

        def _filtered_getaddrinfo(host: Any, port: Any, family: int = 0, type: int = 0, proto: int = 0, flags: int = 0) -> List[Any]:
            if family == socket.AF_UNSPEC or family == 0:
                family = socket.AF_INET
            elif family == socket.AF_INET6:
                raise socket.gaierror(socket.EAI_ADDRFAMILY, "Address family not supported (IPv6 blocked by AnonGuard)")
            res = self._orig_getaddrinfo(host, port, family, type, proto, flags)
            filtered = [r for r in res if r[0] == socket.AF_INET]
            if not filtered:
                raise socket.gaierror(socket.EAI_NONAME, "No IPv4 addresses found (IPv6 blocked by AnonGuard)")
            return filtered

        socket.getaddrinfo = _filtered_getaddrinfo

    def get_guarded_session(self, proxy_url: Optional[str] = None) -> requests.Session:
        """Creates a requests.Session with fail-closed kill switch and proxy mounted."""
        session = requests.Session()
        target_proxy = proxy_url or (self.proxies[0] if self.proxies else f"socks5h://{self.daemon_addr}")

        session.proxies = {
            "http": target_proxy,
            "https": target_proxy,
        }

        adapter = GuardedHTTPAdapter(guard=self)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session
