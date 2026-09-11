"""
anonguard.core.state
~~~~~~~~~~~~~~~~~~~
Formal state machine enforcing zero-leak fail-closed transitions.
"""

from enum import Enum, auto
import threading
from typing import Callable, Dict, List, Optional, Set


class GuardState(Enum):
    """Formal states for AnonGuard lifecycle."""
    UNINITIALIZED = auto()
    VERIFYING = auto()
    ACTIVE_GUARDED = auto()
    RE_ROUTING = auto()
    DROPPED_FAIL_CLOSED = auto()


class StateTransitionError(Exception):
    """Raised when an invalid state transition is attempted."""
    pass


class KillSwitchTrippedError(Exception):
    """Raised when traffic is blocked because the kill switch is active."""
    pass


class AnonymityVerificationError(Exception):
    """Raised when pre-flight or periodic IP leak checks fail."""
    pass


class GuardStateMachine:
    """Thread-safe state machine governing the AnonGuard operational state.
    
    Guarantees that outbound traffic is only permitted when state is strictly
    `ACTIVE_GUARDED`. Any transit failure forces state into `DROPPED_FAIL_CLOSED`.
    """

    # Allowed directed transitions
    _VALID_TRANSITIONS: Dict[GuardState, Set[GuardState]] = {
        GuardState.UNINITIALIZED: {GuardState.VERIFYING, GuardState.ACTIVE_GUARDED},
        GuardState.VERIFYING: {GuardState.ACTIVE_GUARDED, GuardState.DROPPED_FAIL_CLOSED},
        GuardState.ACTIVE_GUARDED: {GuardState.RE_ROUTING, GuardState.DROPPED_FAIL_CLOSED, GuardState.VERIFYING},
        GuardState.RE_ROUTING: {GuardState.ACTIVE_GUARDED, GuardState.DROPPED_FAIL_CLOSED},
        GuardState.DROPPED_FAIL_CLOSED: {GuardState.VERIFYING},  # Recovery only via fresh verification
    }

    def __init__(self, initial_state: GuardState = GuardState.UNINITIALIZED):
        self._state = initial_state
        self._lock = threading.RLock()
        self._listeners: List[Callable[[GuardState, GuardState], None]] = []

    @property
    def current_state(self) -> GuardState:
        with self._lock:
            return self._state

    @property
    def is_guarded(self) -> bool:
        """Returns True only if traffic is actively safe to transit."""
        with self._lock:
            return self._state == GuardState.ACTIVE_GUARDED

    def transition_to(self, new_state: GuardState, reason: str = "") -> None:
        """Transitions state or raises StateTransitionError if invalid."""
        with self._lock:
            old_state = self._state
            if new_state == old_state:
                return

            allowed = self._VALID_TRANSITIONS.get(old_state, set())
            if new_state not in allowed:
                raise StateTransitionError(
                    f"Illegal state transition from {old_state.name} to {new_state.name}. "
                    f"Reason: {reason or 'None provided'}"
                )

            self._state = new_state
            for callback in self._listeners:
                try:
                    callback(old_state, new_state)
                except Exception:
                    pass

    def trip_kill_switch(self, reason: str = "Connection failure") -> None:
        """Immediately transitions state to DROPPED_FAIL_CLOSED."""
        with self._lock:
            self._state = GuardState.DROPPED_FAIL_CLOSED
            for callback in self._listeners:
                try:
                    callback(GuardState.ACTIVE_GUARDED, GuardState.DROPPED_FAIL_CLOSED)
                except Exception:
                    pass

    def add_listener(self, callback: Callable[[GuardState, GuardState], None]) -> None:
        with self._lock:
            self._listeners.append(callback)
