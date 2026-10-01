"""
anonguard.kernel.killswitch
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Fail-closed transport guard preventing any unproxied socket transit.
"""

from typing import Any, Callable, Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from anonguard.core.state import GuardStateMachine, GuardState, KillSwitchTrippedError


class GuardedHTTPAdapter(HTTPAdapter):
    """Custom HTTPAdapter that checks GuardStateMachine before socket transmission."""

    def __init__(self, state_machine: GuardStateMachine, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.state_machine = state_machine

    def send(self, request: Any, *args: Any, **kwargs: Any) -> Any:
        # Enforce fail-closed barrier
        if not self.state_machine.is_guarded:
            current = self.state_machine.current_state.name
            raise KillSwitchTrippedError(
                f"[AnonGuard KillSwitch] Outbound transit blocked: State is {current} (not ACTIVE_GUARDED)"
            )

        try:
            return super().send(request, *args, **kwargs)
        except Exception as exc:
            # Check if this failure indicates proxy death
            err_msg = str(exc).lower()
            if any(term in err_msg for term in ["proxyerror", "socks", "connection refused", "tunnel"]):
                self.state_machine.trip_kill_switch(f"Upstream transport error: {exc}")
                raise KillSwitchTrippedError(
                    f"[AnonGuard KillSwitch] Upstream proxy failed! KillSwitch tripped to prevent leak. Error: {exc}"
                ) from exc
            raise


class KillSwitchSession(requests.Session):
    """requests.Session subclass with integrated fail-closed kill switch."""

    def __init__(self, state_machine: GuardStateMachine, proxy_url: Optional[str] = None):
        super().__init__()
        self.state_machine = state_machine
        self.proxy_url = proxy_url

        if proxy_url:
            self.proxies = {"http": proxy_url, "https": proxy_url}

        # Mount guarded adapter
        adapter = GuardedHTTPAdapter(state_machine=self.state_machine)
        self.mount("http://", adapter)
        self.mount("https://", adapter)

    def request(self, method: str, url: str, *args: Any, **kwargs: Any) -> requests.Response:
        # Extra barrier: verify proxy is actually set if killswitch is active
        if not self.proxies or not self.proxies.get("http"):
            self.state_machine.trip_kill_switch("Attempted request with empty proxy configuration")
            raise KillSwitchTrippedError(
                "[AnonGuard KillSwitch] Refusing to send request: No proxy configured on session!"
            )
        return super().request(method, url, *args, **kwargs)
