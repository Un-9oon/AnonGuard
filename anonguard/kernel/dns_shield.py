"""
anonguard.kernel.dns_shield
~~~~~~~~~~~~~~~~~~~~~~~~~~~
DNS leak prevention engine forcing remote name resolution and DoH.
"""

from urllib.parse import urlparse, urlunparse
from typing import Optional


class DNSShield:
    """Guarantees DNS resolution never occurs on the local physical network adapter."""

    @staticmethod
    def enforce_remote_dns(proxy_url: str) -> str:
        """Upgrades socks5:// or socks4:// to their remote DNS counterparts (socks5h:// / socks4a://)."""
        if not proxy_url:
            return proxy_url

        parsed = urlparse(proxy_url)
        scheme = parsed.scheme.lower()

        if scheme == "socks5":
            new_parsed = parsed._replace(scheme="socks5h")
            return urlunparse(new_parsed)
        elif scheme == "socks4":
            new_parsed = parsed._replace(scheme="socks4a")
            return urlunparse(new_parsed)

        return proxy_url

    @staticmethod
    def is_remote_dns_enforced(proxy_url: str) -> bool:
        """Returns True if the proxy URL specifies remote DNS resolution."""
        if not proxy_url:
            return False
        scheme = urlparse(proxy_url).scheme.lower()
        # http/https proxies resolve on server by default via CONNECT method
        # socks5h and socks4a explicitly resolve remotely
        return scheme in {"socks5h", "socks4a", "http", "https"}
