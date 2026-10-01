"""
anonguard.core.config
~~~~~~~~~~~~~~~~~~~~
Configuration dataclass for AnonGuard operational policies.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class GuardConfig:
    """Configuration policies for the AnonGuard engine."""

    # Zero-leak policy
    strict_killswitch: bool = True
    enforce_remote_dns: bool = True
    disable_ipv6: bool = True
    verify_ip_before_start: bool = True

    # Verification services
    verification_endpoints: List[str] = field(
        default_factory=lambda: [
            "https://api.ipify.org?format=json",
            "https://httpbin.org/ip",
            "https://ifconfig.me/ip",
            "https://icanhazip.com",
        ]
    )
    verification_timeout: float = 8.0

    # Traffic morphing (Anti-correlation)
    enable_jitter: bool = False
    jitter_lambda: float = 0.05  # Poisson rate parameter
    jitter_min_ms: float = 5.0
    jitter_max_ms: float = 45.0
    enable_padding: bool = False
    padding_block_size: int = 512

    # L7 TLS / Header normalization
    ja4_profile: str = "chrome_120"
    strip_leak_headers: bool = True  # X-Forwarded-For, Via, etc.

    # Mesh & Rotation
    auto_rotate_on_block: bool = True
    block_status_codes: List[int] = field(default_factory=lambda: [403, 429, 503])
    max_retries: int = 3
    health_check_timeout: float = 5.0
