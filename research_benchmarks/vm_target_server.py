#!/usr/bin/env python3
"""
AnonGuard: VM Target & Live Packet Inspector
Runs inside the Ubuntu Virtual Machine to inspect real cross-host traffic.
"""

import http.server
import json
import socketserver
import sys
import threading
import time

AUDIT_LOG_PATH = "/home/user/vm_packet_audit.json"
PORT = 18080

packets_captured = []


class VMPacketInspector(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        client_ip, client_port = self.client_address
        headers_dict = dict(self.headers)

        record = {
            "timestamp": time.time(),
            "peer_ip": client_ip,
            "peer_port": client_port,
            "path": self.path,
            "headers": headers_dict,
            "leak_headers_found": [
                h for h in ["x-forwarded-for", "via", "x-real-ip", "cf-connecting-ip", "true-client-ip"]
                if h in [k.lower() for k in headers_dict.keys()]
            ]
        }
        packets_captured.append(record)

        with open(AUDIT_LOG_PATH, "w") as f:
            json.dump(packets_captured, f, indent=2)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        response_body = json.dumps({
            "status": "received_in_vm",
            "peer_ip": client_ip,
            "leak_detected": len(record["leak_headers_found"]) > 0,
            "total_packets_captured": len(packets_captured)
        })
        self.wfile.write(response_body.encode())

    def log_message(self, format, *args):
        pass


def main():
    print(f"[VM Target] Starting live packet inspector on 0.0.0.0:{PORT}...")
    server = socketserver.TCPServer(("0.0.0.0", PORT), VMPacketInspector)
    server.serve_forever()


if __name__ == "__main__":
    main()
