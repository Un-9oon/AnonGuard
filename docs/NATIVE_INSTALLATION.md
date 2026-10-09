# Native Linux Client / Volunteer installation

VMs are optional laboratory fixtures. The package installs `anonguard-setup`,
`anonguard-native-adapter` and `anonguard-browser`; it does not activate a role
or alter network restrictions during package installation.

This administrative profile targets a dedicated Linux device with systemd,
nftables and Python 3. Ubuntu 24.04 LTS is the documented initial deployment
target. macOS/Windows whole-device isolation is not implemented. The native
firewall has not been activated or leak-tested on the user's device in this
change; local helper tests do not certify a host's effective firewall.

## Provision a trusted network

An independent operator must supply authority endpoints, public-key pins and a
quorum exceeding two thirds. Do not trust an unauthenticated downloaded relay
list. The bootstrap is JSON:

```json
{"version":1,"quorum":3,"authorities":[
  {"id":"a1","address":"192.168.1.10:9100","public_key":"REPLACE_WITH_64_HEX_DIGITS"},
  {"id":"a2","address":"192.168.1.11:9100","public_key":"REPLACE_WITH_64_HEX_DIGITS"},
  {"id":"a3","address":"192.168.1.12:9100","public_key":"REPLACE_WITH_64_HEX_DIGITS"},
  {"id":"a4","address":"192.168.1.13:9100","public_key":"REPLACE_WITH_64_HEX_DIGITS"}
]}
```

These placeholders are deliberately invalid. Authenticate the bootstrap digest
through a separate trusted channel; a digest copied from the same untrusted
source does not authenticate it. Deploy authorities and diverse relays/at least
one explicit exit separately. Home NAT volunteers need reachable port forwarding
or an already supported provisioned bridge path; this wizard does not open NAT
or provide a reverse onion relay.

Render without changing the host first:

```sh
anonguard-setup --role client --bootstrap network.json \
  --bootstrap-sha256 TRUSTED_SHA256 --output native-client
anonguard-setup --role volunteer --bootstrap network.json \
  --bootstrap-sha256 TRUSTED_SHA256 --relay-advertise PUBLIC_IP:9443 \
  --output native-volunteer
```

Review rendered units, authority pins and firewall. From the device's local
console, an administrator can substitute `--apply` for `--output ...`. This
requires installed dependencies and refuses existing service/state migration,
SSH sessions and configuration replacement. Without `--role`, the interactive
wizard asks Client or Volunteer. A volunteer is a non-exit relay by default and
does not activate the client firewall. Full service readiness/consensus admission
is not established merely by `systemctl start`.

## Client behavior and limits

The native client enables balanced padded sessions. A dedicated transport UID
can establish backend TCP; an adapter UID can only contact loopback SOCKS and
reply to adapter clients. Ordinary IPv4 TCP is transparently redirected through
SOCKS. DNS UDP/TCP port 53 is redirected to a local adapter which resolves through
certificate-verified DNS-over-TLS at Cloudflare over the onion circuit; resolver
failure returns SERVFAIL. This is one explicit resolver dependency, not resolver
anonymity or a distributed DNS design. Direct non-DNS UDP, QUIC and IPv6 are
blocked. DNS-over-HTTPS from applications is ordinary proxied TCP. DHCP is a
network-management exception and can reveal device/network information.

The rules manage only `inet anonguard_native`, preserving other tables, which
can still block legitimate traffic. There is no blanket established-output
allowance. Firewall restrictions survive backend death, service stop and package
removal. Activation orders restrictions before backend/adapter. Failures may
leave partial configuration: inspect at the console and keep restrictions while
repairing it. Do not delete the table to obtain direct application connectivity.
Account identities are fixed and created with systemd-sysusers.

This trusts the host administrator, kernel, transport UID, systemd and installed
helpers. It is not protection against root malware, stolen sessions, arbitrary
host IPC brokers, inherited privileged sockets or kernel escapes. The existing
restricted headless application/optional VM profiles offer different boundaries.
Privileged services must be audited independently. Client mode restricts LAN
services and can interrupt ordinary desktop applications; use a dedicated device
and retain console access.

## Native browser

Render a native loopback policy with:

```sh
anonguard-browser --native-client --emit-policy policies.json
```

Install this policy at the Firefox ESR policy location as an administrator, with
root ownership/protected ancestors and mode 0644 so the ordinary browser user can read it. The public native device profile is also installed as 0644; environment configuration remains private. As an ordinary user, run
`anonguard-browser --native-client --check`, then `--launch`. The helper requires
an authenticated native client profile and active firewall/client/adapter units.
It validates policy configuration and browser installation; actual policy loading
must be inspected in Firefox `about:policies` during acceptance. Disposable
profiles, remote DNS, RFP/letterboxing and blocked WebRTC/QUIC are configured;
this is not a Tor Browser-equivalent audited browser distribution.

Before acceptance, test boot ordering, DNS/IPv6/UDP leaks, pre-existing sockets,
backend/adapter death, suspend/resume, firewall reload, install/upgrade/removal,
new network attachment and browser policy enforcement on the actual device.
No deployment-accepted status is generated automatically.
