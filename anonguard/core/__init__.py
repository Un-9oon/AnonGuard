"""
anonguard.core
~~~~~~~~~~~~~~
Core state machine and configuration for AnonGuard.
"""

from anonguard.core.state import (
    GuardState,
    GuardStateMachine,
    StateTransitionError,
    KillSwitchTrippedError,
    AnonymityVerificationError,
)
from anonguard.core.config import GuardConfig

__all__ = [
    "GuardState",
    "GuardStateMachine",
    "StateTransitionError",
    "KillSwitchTrippedError",
    "AnonymityVerificationError",
    "GuardConfig",
]
