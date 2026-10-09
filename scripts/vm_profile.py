#!/usr/bin/python3 -I
"""Render an offline two-VM SOCKS-only Linux profile; never install or change networking."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import sys


def interface(value):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}", value) or value == "lo":
        raise ValueError("Interface must be a concrete non-loopback Linux interface name")
    return value


def validate(internal, wan, application_interface, subnet, gateway, application, port):
    internal, wan = interface(internal), interface(wan)
    application_interface = interface(application_interface)
    if internal == wan:
        raise ValueError("Gateway internal and WAN interfaces must differ")
    network = ipaddress.IPv4Network(subnet, strict=True)
    private = [ipaddress.IPv4Network(value) for value in
               ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    if not 24 <= network.prefixlen <= 30 or not any(network.subnet_of(n) for n in private):
        raise ValueError("Internal subnet must be an RFC1918 IPv4 /24 through /30")
    gateway, application = ipaddress.IPv4Address(gateway), ipaddress.IPv4Address(application)
    for address in (gateway, application):
        if address not in network or address in (network.network_address, network.broadcast_address):
            raise ValueError("VM addresses must be usable hosts in the internal subnet")
    if gateway == application or not 1024 <= port <= 65535:
        raise ValueError("VM addresses must differ and SOCKS port must be 1024..65535")
    return internal, wan, application_interface, network, gateway, application, port


def firewall(role, internal, wan, gateway, application, port):
    # add is idempotent; flush removes only our rules. The whole nft file is one
    # transaction, so reload never exposes an intermediate empty policy.
    prefix = "add table inet anonguard_vm\nflush table inet anonguard_vm\n"
    chains = {
        "input": ['iifname "lo" accept', 'ct state invalid drop'],
        "output": ['oifname "lo" accept', 'ct state invalid drop'],
        "forward": [],
    }
    if role == "gateway":
        chains["input"] += [
            f'iifname "{wan}" ct state established,related accept',
            f'iifname "{wan}" udp sport 67 udp dport 68 accept',
            f'iifname "{internal}" ip saddr {application} ip daddr {gateway} '
            f'tcp dport {port} ct state new,established accept',
        ]
        chains["output"] += [
            f'oifname "{wan}" accept',
            f'oifname "{internal}" ip saddr {gateway} ip daddr {application} '
            f'tcp sport {port} ct state established accept',
        ]
    else:
        chains["input"] += [
            f'iifname "{internal}" ip saddr {gateway} ip daddr {application} '
            f'tcp sport {port} ct state established accept',
        ]
        chains["output"] += [
            f'oifname "{internal}" ip saddr {application} ip daddr {gateway} '
            f'tcp dport {port} ct state new,established accept',
        ]
    result = prefix
    for name, rules in chains.items():
        result += (f"add chain inet anonguard_vm {name} "
                   f"{{ type filter hook {name} priority -10; policy drop; }}\n")
        result += "".join(f"add rule inet anonguard_vm {name} {rule}\n" for rule in rules)
    return result


FIREWALL_UNIT = """[Unit]
Description=AnonGuard VM SOCKS-only network boundary
DefaultDependencies=no
Wants=network-pre.target
Before=network-pre.target shutdown.target
Conflicts=shutdown.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f /etc/anonguard/vm.nft
ExecReload=/usr/sbin/nft -f /etc/anonguard/vm.nft
RemainAfterExit=yes
# No ExecStop: restrictions remain after service stop or gateway crash.

[Install]
WantedBy=multi-user.target
"""


def render(internal, wan, application_interface, network, gateway, application, port):
    files = {}
    for role, address in (("gateway", gateway), ("application", application)):
        base = f"{role}/"
        nic = internal if role == "gateway" else application_interface
        files[base + "etc/anonguard/vm.nft"] = firewall(
            role, nic, wan, gateway, application, port)
        files[base + "etc/systemd/system/anonguard-vm-firewall.service"] = FIREWALL_UNIT
        files[base + "etc/systemd/network/10-anonguard-internal.network"] = f"""[Match]
Name={nic}

[Network]
Address={address}/{network.prefixlen}
DHCP=no
LinkLocalAddressing=no
IPv6AcceptRA=no
IPForward=no
"""
        files[base + "etc/sysctl.d/90-anonguard-vm.conf"] = """net.ipv4.ip_forward=0
net.ipv6.conf.all.forwarding=0
net.ipv6.conf.default.forwarding=0
"""
        files[base + "etc/systemd/system/systemd-networkd.service.d/anonguard.conf"] = """[Unit]
Requires=anonguard-vm-firewall.service
After=anonguard-vm-firewall.service
"""
    files["gateway/etc/systemd/network/20-anonguard-wan.network"] = f"""[Match]
Name={wan}

[Network]
DHCP=ipv4
LinkLocalAddressing=no
IPv6AcceptRA=no
IPForward=no
"""
    files["gateway/etc/systemd/system/anonguard.service.d/vm-boundary.conf"] = """[Unit]
BindsTo=anonguard-vm-firewall.service
After=anonguard-vm-firewall.service
"""
    files["gateway/etc/systemd/system/anonguard-vm-proxy.socket"] = f"""[Unit]
Description=Private application-VM AnonGuard SOCKS endpoint
BindsTo=anonguard-vm-firewall.service anonguard.service
After=anonguard-vm-firewall.service anonguard.service network-online.target

[Socket]
ListenStream={gateway}:{port}
FreeBind=no
Accept=no
Backlog=64

[Install]
WantedBy=multi-user.target
"""
    files["gateway/etc/systemd/system/anonguard-vm-proxy.service"] = """[Unit]
Description=Private SOCKS endpoint to loopback AnonGuard gateway
BindsTo=anonguard-vm-firewall.service anonguard.service
After=anonguard-vm-firewall.service anonguard.service

[Service]
ExecStart=/usr/lib/systemd/systemd-socket-proxyd --connections-max=64 127.0.0.1:9050
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_INET AF_UNIX
CapabilityBoundingSet=
LimitCORE=0
TasksMax=32
MemoryMax=128M
"""
    files["application/proxy.env"] = f"""# Applications must support SOCKS remote DNS; this does not configure browsers.
ALL_PROXY=socks5h://{gateway}:{port}
all_proxy=socks5h://{gateway}:{port}
NO_PROXY=
no_proxy=
"""
    files["profile.json"] = json.dumps({
        "version": 1, "internal_interface": internal, "wan_interface": wan,
        "application_interface": application_interface,
        "subnet": str(network), "gateway": str(gateway), "application": str(application),
        "port": port, "daemon_endpoint": "127.0.0.1:9050",
        "deployment_accepted": False, "browser_hardening_included": False,
        "requires": "Separate VMs, internal-only application NIC, trusted host and operator",
        "sha256": {path: hashlib.sha256(content.encode()).hexdigest()
                   for path, content in sorted(files.items())},
    }, indent=2) + "\n"
    return files


def write_new(destination, files):
    # Never replace an existing profile or follow a final output-directory symlink.
    destination.mkdir(mode=0o700)
    try:
        for relative, content in files.items():
            path = destination / relative
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with path.open("x", encoding="utf-8") as stream:
                os.chmod(path, 0o600)
                stream.write(content)
    except BaseException:
        shutil.rmtree(destination)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--internal-interface", required=True)
    parser.add_argument("--wan-interface", required=True)
    parser.add_argument("--application-interface", required=True)
    parser.add_argument("--subnet", default="10.77.0.0/24")
    parser.add_argument("--gateway", default="10.77.0.1")
    parser.add_argument("--application", default="10.77.0.2")
    parser.add_argument("--port", type=int, default=9050)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        values = validate(args.internal_interface, args.wan_interface, args.application_interface, args.subnet,
                          args.gateway, args.application, args.port)
        write_new(args.output, render(*values))
    except (ValueError, OSError) as error:
        print(f"Profile refused: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"profile_created": True, "deployment_accepted": False,
                      "output": str(args.output.resolve())}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
