"""
anonguard.kernel.ipv6_blocker
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Suppresses dual-stack IPv6 fallback leaks at the socket abstraction layer.
"""

import socket
from typing import Any, Callable, List, Optional


class IPv6Blocker:
    """Blocks IPv6 name resolution to prevent dual-stack leakage when proxies are IPv4 only."""

    _orig_getaddrinfo: Optional[Callable[..., Any]] = None
    _active: bool = False

    @classmethod
    def enable(cls) -> None:
        """Patches socket.getaddrinfo to strictly filter out AF_INET6 records."""
        if cls._active:
            return

        cls._orig_getaddrinfo = socket.getaddrinfo

        def _filtered_getaddrinfo(
            host: Any, port: Any, family: int = 0, type: int = 0, proto: int = 0, flags: int = 0
        ) -> List[Any]:
            # Force IPv4 family
            if family == socket.AF_UNSPEC or family == 0:
                family = socket.AF_INET
            elif family == socket.AF_INET6:
                raise socket.gaierror(socket.EAI_ADDRFAMILY, "Address family for hostname not supported (IPv6 blocked by AnonGuard)")

            res = cls._orig_getaddrinfo(host, port, family, type, proto, flags)
            # Extra filter to ensure no AF_INET6 survives
            filtered = [r for r in res if r[0] == socket.AF_INET]
            if not filtered:
                raise socket.gaierror(socket.EAI_NONAME, "No IPv4 addresses found (IPv6 blocked by AnonGuard)")
            return filtered

        socket.getaddrinfo = _filtered_getaddrinfo
        cls._active = True

    @classmethod
    def disable(cls) -> None:
        """Restores original socket.getaddrinfo."""
        if not cls._active:
            return
        if cls._orig_getaddrinfo is not None:
            socket.getaddrinfo = cls._orig_getaddrinfo
            cls._orig_getaddrinfo = None
        cls._active = False

    @classmethod
    def is_active(cls) -> bool:
        return cls._active
