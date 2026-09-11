"""
anonguard.crypto_tls.ja4_profiles
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
JA4 / JA3 browser TLS fingerprint profile generator.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class TLSProfile:
    """Represents a target browser TLS signature."""
    name: str
    ja3_string: str
    ja4_string: str
    ciphers: str
    alpn_protocols: List[str]
    user_agent: str


# Standard realistic browser profiles
BROWSER_PROFILES: Dict[str, TLSProfile] = {
    "chrome_120": TLSProfile(
        name="Chrome 120 (Windows 10/11)",
        ja3_string="771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
        ja4_string="t13d1516h2_8daaf6152771_0266399c6478",
        ciphers="TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384",
        alpn_protocols=["h2", "http/1.1"],
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    ),
    "firefox_124": TLSProfile(
        name="Firefox 124 (Windows 10/11)",
        ja3_string="771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-43-45-51-27-21,29-23-24-25-256-257,0",
        ja4_string="t13d1715h2_e8f1e7e7833a_b556b6b72a6b",
        ciphers="TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256",
        alpn_protocols=["h2", "http/1.1"],
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    ),
}


class JA4ProfileEngine:
    """Manages browser TLS profiles and applies them to outbound sessions."""

    @classmethod
    def get_profile(cls, name: str = "chrome_120") -> TLSProfile:
        return BROWSER_PROFILES.get(name, BROWSER_PROFILES["chrome_120"])

    @classmethod
    def list_available_profiles(cls) -> List[str]:
        return list(BROWSER_PROFILES.keys())
