# Two-VM SOCKS-only Linux deployment profile

This profile separates a potentially hostile application from the gateway OS.
It is an offline-generated deployment candidate, not a validated VM appliance,
hardened browser, transparent VPN or production anonymity certification. Live
acceptance is deferred; do not mark the checklist passed merely by generating files.

## Boundary

```text
Application VM -- private internal network -- Gateway VM -- WAN -- AnonGuard relays
        SOCKS5 remote DNS only                  loopback daemon
```

Use two separate Ubuntu 24.04 LTS VMs on a trusted, updated hypervisor. The
application VM gets exactly one adapter in a named VirtualBox **Internal Network**.
The gateway gets one adapter on that same internal network and one WAN adapter,
normally NAT. An Internal Network is different from NAT Network, bridged and
host-only networking. Do not give the application a second adapter, USB network
device, host networking, shared folders, clipboard, drag-and-drop, guest-to-host
brokers or personal credentials. Keep other VMs off this internal network.

Provision packages while building trusted images, then detach the application's
internet adapter **while powered off**, before any protected session. Guest firewall
rules cannot prove hypervisor adapter configuration. The administrator must check
the topology from the host; a compromised guest can lie about its own inventory.

The application has a static IPv4 address, no default route, no configured DNS,
no DHCP and no IPv6 router discovery/link-local addressing. Its firewall allows
only TCP to the fixed gateway SOCKS endpoint and matching replies. Even pre-existing
non-proxy connections are not admitted by a blanket established-flow exception.
Loopback remains available inside each VM; it does not connect to host/gateway IPC.

The gateway rejects all forwarded IPv4/IPv6 packets. Its internal interface admits
only the configured application IP to the SOCKS port. A bounded systemd socket
proxy forwards that endpoint to the existing daemon at **127.0.0.1:9050**; the daemon
does not need `--allow-open-socks5`. This is trusted-network access control, not
cryptographic authentication between VMs. It assumes the host and internal network
are trusted. A compromised host or another attached VM can defeat those assumptions.

## Generate and inspect

On the development system, identify the **actual** interface names separately in
both guests. The following example uses gateway `enp0s8` internal / `enp0s3` WAN,
and application `enp0s3` internal; yours may differ:

```sh
python3 scripts/vm_profile.py \
  --internal-interface enp0s8 --wan-interface enp0s3 \
  --application-interface enp0s3 \
  --subnet 10.77.0.0/24 --gateway 10.77.0.1 --application 10.77.0.2 \
  --output /tmp/anonguard-two-vm
```

The destination must not exist. Addresses must be distinct usable hosts in an
RFC1918 /24.. /30 subnet; avoid overlap with host/WAN networks. Parameters cannot
inject firewall syntax. `profile.json` records parameters and file hashes, but is
not a signed image or proof of origin. The generator changes no active firewall,
service or interface. Preserve a reviewed copy of the profile.

## Install on dedicated guests, from their consoles

These files target **systemd-networkd**. Do not apply them to an existing host or
through your only SSH connection: they intentionally disallow inbound SSH. First
resolve competing Netplan/NetworkManager/networkd match files on the disposable
guests; an earlier matching `.network` file can override the generated static
configuration. Do not run multiple network managers or firewall writers for this
profile. Keep the host's firewall unchanged. Reserve `inet anonguard_vm` for these
rules; never run a global `nft flush ruleset` while protected sessions are active.

Gateway prerequisites: verified AnonGuard Debian package, `nftables`, systemd with
`/usr/lib/systemd/systemd-socket-proxyd`, and systemd-networkd. Application prerequisites:
`nftables`, systemd-networkd and the intended application. Install dependencies
before network restrictions. Disable unneeded guest services and integrations.

Inspect and copy only `gateway/etc/` into the gateway's `/etc/`, and only
`application/etc/` into the application's `/etc/`. Keep files root-owned and
non-writable by application users. Existing daemon installation/state must be
preserved. Configure authenticated authority endpoints, pins, quorum and any
bridge/retirement policy in `/etc/anonguard/runtime.env`; do not include duplicate
`--listen` flags, raw proxy modes, `--allow-open-socks5` or `--allow-private-exit`.
The existing daemon service supplies its loopback listener. This profile does not
provision authorities, relays, credentials or browser binaries.

After installing the role's files, from each guest console:

```sh
sudo systemctl daemon-reload
sudo nft --check --file /etc/anonguard/vm.nft
sudo systemctl enable --now anonguard-vm-firewall.service
sudo sysctl --load /etc/sysctl.d/90-anonguard-vm.conf
sudo systemctl enable systemd-networkd.service
```

The nft check needs privileges and validates the target kernel's rules. Start/restart
networkd from the console only after the firewall is active and competing network
configuration has been resolved. Confirm the intended static addresses, interfaces
and absence of an application default route. On the gateway, with real daemon
configuration ready:

```sh
sudo systemctl start systemd-networkd.service
sudo systemctl enable --now anonguard-vm-proxy.socket
```

On the application, start systemd-networkd from its console. The networkd drop-in
requires successful firewall setup. Firewall changes load in one nft transaction,
replacing only this profile's rules. Stopping its systemd unit does not remove
rules. Gateway daemon/firewall loss stops the private socket/proxy dependencies;
applications lose service rather than gain direct internet. After fixing the
failure, explicitly restart the firewall/daemon/private socket as appropriate.
Do not claim seamless stream recovery; interrupted transactions can fail.

## Application compatibility and browser scope

Applications must support SOCKS5 with **remote hostname resolution**. For curl:

```sh
curl --proxy socks5h://10.77.0.1:9050 --noproxy '' https://example.com/
```

The generated `application/proxy.env` is optional shell configuration for tools
that honor those variables. It is not an enforced routing mechanism, does not
configure Firefox, and does not automatically proxy arbitrary applications.
Direct DNS, UDP, QUIC and applications ignoring SOCKS should fail. Perform updates
through a supported proxy or authenticated offline image replacement, never by
temporarily adding a direct application internet adapter during a protected session.

A browser still needs a maintained standardized fingerprint profile, remote-DNS
proxy configuration, storage/identity isolation, WebRTC controls and security
updates. This profile does not implement those protections. Keep the browser's
own sandbox enabled. Do not publish a browser-fingerprinting resistance claim.

## Required live acceptance record

- Record exact commit/artifact, host/hypervisor versions, both guest kernels,
  adapter settings, interface names, addresses, routes, active units and rules.
- Verify a permitted SOCKS request through a real circuit; compare the destination's
  observed address with the exit, not with the application/host address.
- Verify direct IPv4, IPv6, DNS TCP/UDP, QUIC and connections to every other gateway
  port are denied. Capture on the private segment **and gateway WAN**.
- Repeat after gateway daemon/proxy termination, firewall-unit stop, failed firewall
  reload, guest reboot and gateway outage; verify restrictions remain and no direct
  fallback occurs. A killed process alone does not prove every failure mode.
- Verify file/clipboard/IPC/USB integration boundaries from both host and guest.
  Test a privileged application-guest attacker separately from an ordinary app.
- Measure resource exhaustion and recovery with the 64-connection proxy limit and
  daemon budgets. Preserve guard, key and retirement state through upgrades.

This boundary reduces exposure of the gateway OS to application compromise; it
does not defeat host/hypervisor exploits, user account identification, malicious
browser behavior over allowed SOCKS traffic, global timing correlation or a
malicious gateway. Native Windows/macOS containment remains outside this profile.

References: [VirtualBox internal networks](https://docs.oracle.com/en/virtualization/virtualbox/6.0/user/network_internal.html),
[nftables command and chain semantics](https://netfilter.org/projects/nftables/manpage.html).
