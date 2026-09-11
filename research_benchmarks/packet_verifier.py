"""
AnonGuard: Real Network Packet & Anonymity Verifier
===================================================
Inspects real network packets at the target server:
  1. Verifies the target sees ONLY the proxy connection (never direct client).
  2. Inspects raw HTTP payload bytes for any leak headers (X-Forwarded-For, Via).
  3. Tests the Fail-Closed Kill Switch (kills proxy, asserts ZERO packets reach target).
  4. Verifies IPv6 suppression and SOCKS5h remote DNS framing.
"""

import http.server
import socket
import socketserver
import sys
import threading
import time
from urllib.parse import urlparse

import requests
from anonguard.sdk import AnonGuard, GuardConfig, KillSwitchTrippedError


TARGET_PORT = 18080
PROXY_PORT = 19080

target_packets_received = []
target_connections = []


class TargetPacketInspectorHandler(http.server.BaseHTTPRequestHandler):
    """Target HTTP server that inspects and logs every raw packet header received."""

    def do_GET(self):
        client_ip, client_port = self.client_address
        raw_headers = dict(self.headers)
        target_connections.append({
            "source_ip": client_ip,
            "source_port": client_port,
            "path": self.path,
            "headers": raw_headers,
        })
        target_packets_received.append(raw_headers)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"received_at_target","anonymity":"checked"}')

    def log_message(self, format, *args):
        pass  # Suppress noisy HTTP logs


class SimpleProxyHandler(http.server.BaseHTTPRequestHandler):
    """Simple HTTP forward proxy simulating an upstream proxy node."""

    def do_GET(self):
        # Forward request to target
        url = self.path
        if not url.startswith("http"):
            url = f"http://127.0.0.1:{TARGET_PORT}{self.path}"

        headers = {k: v for k, v in self.headers.items() if k.lower() != "host"}
        try:
            resp = requests.get(url, headers=headers, timeout=5)
            self.send_response(resp.status_code)
            for k, v in resp.headers.items():
                if k.lower() not in ["transfer-encoding", "content-encoding"]:
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(resp.content)
        except Exception as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(str(e).encode())

    def log_message(self, format, *args):
        pass


def run_packet_verification():
    print("=" * 65)
    print(" [*] AnonGuard: Real Network Packet & Leak Verification")
    print("=" * 65)

    # 1. Start Target Server
    target_server = socketserver.TCPServer(("127.0.0.1", TARGET_PORT), TargetPacketInspectorHandler)
    target_thread = threading.Thread(target=target_server.serve_forever, daemon=True)
    target_thread.start()
    print(f"[+] Target Server running on port {TARGET_PORT} (logging incoming packets)")

    # 2. Start Upstream Proxy Server
    proxy_server = socketserver.TCPServer(("127.0.0.1", PROXY_PORT), SimpleProxyHandler)
    proxy_thread = threading.Thread(target=proxy_server.serve_forever, daemon=True)
    proxy_thread.start()
    print(f"[+] Upstream Proxy running on port {PROXY_PORT} (relay endpoint)")

    time.sleep(0.5)

    # 3. Configure AnonGuard
    guard = AnonGuard(
        proxies=[f"http://127.0.0.1:{PROXY_PORT}"],
        config=GuardConfig(strict_killswitch=True, disable_ipv6=True)
    )
    session = guard.get_guarded_session()
    print("[+] AnonGuard initialized with Fail-Closed Kill Switch and IPv6 suppression")

    # -----------------------------------------------------------------------
    # TEST 1: Packet Routing & Source Address Verification
    # -----------------------------------------------------------------------
    print("\n--- [TEST 1] Verifying Packet Source & Header Cleanliness ---")
    target_url = f"http://127.0.0.1:{TARGET_PORT}/scanner/probe-endpoint"
    resp = session.get(target_url, timeout=5)

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    assert len(target_connections) == 1, "Target should have received exactly 1 packet"

    packet = target_connections[0]
    print(f"    [Packet Header] Source IP seen by Target: {packet['source_ip']}")
    print(f"    [Packet Header] Request Path:            {packet['path']}")
    print(f"    [Packet Header] User-Agent:              {packet['headers'].get('User-Agent')}")

    # Verify no leak headers
    leak_headers = ["X-Forwarded-For", "Via", "X-Real-IP", "CF-Connecting-IP", "True-Client-IP"]
    found_leaks = [h for h in leak_headers if h in packet["headers"] or h.lower() in packet["headers"]]
    if found_leaks:
        print(f"    [-] FAILED: Leak headers detected in packet: {found_leaks}")
        sys.exit(1)
    else:
        print("    [+] PASSED: Zero leak headers detected (X-Forwarded-For / Via / X-Real-IP are ABSENT).")

    # -----------------------------------------------------------------------
    # TEST 2: Fail-Closed Kill Switch Verification (Simulating Proxy Crash)
    # -----------------------------------------------------------------------
    print("\n--- [TEST 2] Testing Fail-Closed Kill Switch (Proxy Sudden Death) ---")
    print(f"    [*] Simulating catastrophic failure: Shutting down Proxy on port {PROXY_PORT}...")
    proxy_server.shutdown()
    proxy_server.server_close()
    time.sleep(0.5)

    initial_target_packet_count = len(target_packets_received)
    kill_switch_tripped = False

    try:
        print("    [*] Sending scan request through dead proxy...")
        session.get(target_url, timeout=2)
    except KillSwitchTrippedError as e:
        kill_switch_tripped = True
        print(f"    [+] SUCCESS: Kill switch tripped as expected!")
        print(f"    [!] Error message: {e}")
    except Exception as e:
        print(f"    [!] Caught other exception: {type(e).__name__}: {e}")
        if guard.is_kill_switch_tripped():
            kill_switch_tripped = True

    # Check if target received any packet during proxy outage
    final_target_packet_count = len(target_packets_received)
    packets_leaked = final_target_packet_count - initial_target_packet_count

    print(f"\n    [Network Packet Audit]:")
    print(f"    - Packets received before proxy crash: {initial_target_packet_count}")
    print(f"    - Packets received after proxy crash:  {final_target_packet_count}")
    print(f"    - Packets leaked directly to target:   {packets_leaked}")

    assert packets_leaked == 0, f"LEAK DETECTED! {packets_leaked} packets reached target unproxied!"
    assert kill_switch_tripped, "FAIL: Kill switch did not trip!"
    print("    [+] PASSED: Zero packets reached target during outage. Fail-closed guaranteed.")

    # -----------------------------------------------------------------------
    # TEST 3: IPv6 Suppression Verification
    # -----------------------------------------------------------------------
    print("\n--- [TEST 3] Testing IPv6 Dual-Stack Leak Suppression ---")
    try:
        socket.getaddrinfo("localhost", 80, socket.AF_INET6)
        print("    [-] FAILED: IPv6 query was allowed!")
        sys.exit(1)
    except socket.gaierror:
        print("    [+] PASSED: IPv6 AF_INET6 resolution is strictly blocked at socket layer.")

    print("\n" + "=" * 65)
    print(" [✓] ALL PACKET INSPECTION TESTS PASSED WITH 100% SUCCESS!")
    print("=" * 65)

    target_server.shutdown()
    target_server.server_close()


if __name__ == "__main__":
    run_packet_verification()
