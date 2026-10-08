#!/usr/bin/env python3
"""Supervise an operator-installed obfs4 PT; publish private bindings only when ready."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import time


def address(value, loopback=False):
    if not isinstance(value, str):
        raise ValueError("endpoint must be numeric IP:port")
    host, port = value.rsplit(":", 1)
    if (":" in host and not (host.startswith("[") and host.endswith("]"))) or (
            ":" not in host and ("[" in host or "]" in host)):
        raise ValueError("invalid endpoint framing")
    ip = ipaddress.ip_address(host[1:-1] if host.startswith("[") else host)
    if not port.isdecimal() or not 0 < int(port) <= 65535 or (loopback and not ip.is_loopback):
        raise ValueError("invalid endpoint")
    return value


def notify(message):
    endpoint = os.environ.get("NOTIFY_SOCKET")
    if endpoint:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as channel:
            channel.connect("\0" + endpoint[1:] if endpoint.startswith("@") else endpoint)
            channel.sendall(message.encode())


def private_json(path, value):
    descriptor, temporary = tempfile.mkstemp(prefix=".pt-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as output:
            json.dump(value, output)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def bindings(values, maximum):
    if not isinstance(values, list) or not 1 <= len(values) <= maximum:
        raise ValueError("invalid binding count")
    pins = set()
    for item in values:
        if not isinstance(item, dict) or set(item) != {"identity", "bridge", "arguments"}:
            raise ValueError("invalid binding fields")
        pin = item["identity"]
        if (not isinstance(pin, list) or len(pin) != 32 or
                any(type(byte) is not int or not 0 <= byte <= 255 for byte in pin) or
                not any(pin) or tuple(pin) in pins):
            raise ValueError("invalid binding pin")
        pins.add(tuple(pin))
        address(item["bridge"])
        if (not isinstance(item["arguments"], dict) or not item["arguments"] or
                any(not isinstance(k, str) or not k or not isinstance(v, str)
                    for k, v in item["arguments"].items())):
            raise ValueError("invalid PT arguments")
    return values


def supervise(config, state, runtime):
    if config.get("mode") not in {"client", "server"}:
        raise ValueError("mode must be client or server")
    binary = Path(config.get("binary", "/usr/bin/obfs4proxy")).resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError("transport binary must be an installed executable")
    for path in (state, runtime):
        if not path.is_absolute():
            raise ValueError("state/runtime paths must be absolute")
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        if ((path.is_symlink() and path.lstat().st_uid != 0) or
                path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077):
            raise ValueError("state/runtime directories must be private and owned by this account")
    outputs = [runtime / name for name in ("bridges.json", "authorities.json", "server.json")]
    for output in outputs:
        output.unlink(missing_ok=True)
    environment = {"TOR_PT_MANAGED_TRANSPORT_VER": "1", "TOR_PT_STATE_LOCATION": str(state),
                   "TOR_PT_EXIT_ON_STDIN_CLOSE": "1"}
    mode = config["mode"]
    if mode == "client":
        if set(config) - {"mode", "binary", "bridges", "authorities"}:
            raise ValueError("unknown client configuration fields")
        entries = bindings(config.get("bridges"), 3)
        authorities = bindings(config.get("authorities"), 16)
        environment["TOR_PT_CLIENT_TRANSPORTS"] = "obfs4"
    else:
        if set(config) != {"mode", "binary", "listen", "backend"}:
            raise ValueError("invalid server configuration fields")
        environment.update(TOR_PT_SERVER_TRANSPORTS="obfs4",
                           TOR_PT_SERVER_BINDADDR="obfs4-" + address(config["listen"]),
                           TOR_PT_ORPORT=address(config["backend"], loopback=True))
    stopped = False

    def stop(_signal, _frame):
        nonlocal stopped
        stopped = True

    previous = {sig: signal.signal(sig, stop) for sig in (signal.SIGINT, signal.SIGTERM)}
    child = None
    selector = selectors.DefaultSelector()
    try:
        child = subprocess.Popen([str(binary)], env=environment, stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 start_new_session=True)
        selector.register(child.stdout, selectors.EVENT_READ)
        os.set_blocking(child.stdout.fileno(), False)
        buffer = b""
        deadline = time.monotonic() + 15
        version = False
        method = None
        ready = False
        messages = 0
        while not stopped:
            if child.poll() is not None:
                raise RuntimeError("transport exited")
            if not ready and time.monotonic() >= deadline:
                raise RuntimeError("transport startup timed out")
            for key, _ in selector.select(timeout=0.2):
                chunk = os.read(key.fileobj.fileno(), 4096)
                if not chunk:
                    raise RuntimeError("transport control channel closed")
                buffer += chunk
                if len(buffer) > 16384:
                    raise RuntimeError("transport control output exceeded limits")
                while b"\n" in buffer:
                    raw, buffer = buffer.split(b"\n", 1)
                    if len(raw) > 4096:
                        raise RuntimeError("oversized transport message")
                    if ready:
                        continue  # Drain diagnostics without recording addresses/certificates.
                    messages += 1
                    if messages > 64:
                        raise RuntimeError("too many transport startup messages")
                    fields = raw.decode("ascii").strip().split()
                    if not fields:
                        continue
                    if "ERROR" in fields[0]:
                        raise RuntimeError("transport startup rejected configuration")
                    if fields == ["VERSION", "1"]:
                        version = True
                    elif fields[0] == ("CMETHOD" if mode == "client" else "SMETHOD"):
                        if method is not None or len(fields) < 3 or fields[1] != "obfs4":
                            raise RuntimeError("unexpected transport method")
                        method = fields
                    elif fields == [("CMETHODS" if mode == "client" else "SMETHODS"), "DONE"]:
                        if not version or method is None:
                            raise RuntimeError("incomplete transport initialization")
                        if mode == "client":
                            if len(method) != 4 or method[2] != "socks5":
                                raise RuntimeError("transport must provide SOCKS5")
                            proxy = address(method[3], loopback=True)
                            private_json(outputs[0], [dict(entry, proxy=proxy) for entry in entries])
                            private_json(outputs[1], [dict(entry, proxy=proxy) for entry in authorities])
                        else:
                            endpoint = address(method[2])
                            if len(method) != 4 or not method[3].startswith("ARGS:"):
                                raise RuntimeError("server must provide obfs4 arguments")
                            arguments = dict(pair.split("=", 1) for pair in method[3][5:].split(","))
                            private_json(outputs[2], {"listen": endpoint, "arguments": arguments})
                        ready = True
                        notify("READY=1")
        return 0
    finally:
        for output in outputs:
            output.unlink(missing_ok=True)
        if child is not None:
            if child.stdin:
                child.stdin.close()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                # Only signal the new process group created for this PT instance.
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
        selector.close()
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    args = parser.parse_args()
    try:
        with args.config.open("rb") as source:
            data = source.read(65537)
        if len(data) > 65536:
            raise ValueError("configuration exceeds 64 KiB")
        config = json.loads(data)
        if not isinstance(config, dict):
            raise ValueError("configuration must be an object")
        return supervise(config, args.state, args.runtime)
    except (OSError, ValueError, RuntimeError):
        # Configuration/control messages can contain private endpoints; do not echo them.
        print("PT supervision failed; check installed binary and private configuration", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
