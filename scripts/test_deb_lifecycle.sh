#!/usr/bin/env bash
# Run only on a disposable CI host: this installs and purges the package.
set -euo pipefail
if [[ "${ANONGUARD_DISPOSABLE_PACKAGE_TEST:-}" != "1" || "$EUID" != "0" ]]; then
    echo 'Requires root and ANONGUARD_DISPOSABLE_PACKAGE_TEST=1 on a disposable host' >&2
    exit 2
fi
if [[ "$#" != "1" || ! -f "$1" ]]; then
    echo 'Usage: test_deb_lifecycle.sh PACKAGE.deb' >&2
    exit 2
fi
if dpkg-query -W -f='${Status}' anonguard 2>/dev/null | grep -q 'install ok installed'; then
    echo 'Refusing to replace an existing installation' >&2
    exit 2
fi
# Exclusive disposable fixture ownership; never clear existing operator state.
if [[ -e /var/lib/anonguard ]]; then
    echo 'Refusing to overwrite pre-existing persistent AnonGuard state' >&2
    exit 2
fi
fixture_root=$(mktemp -d)
state_created=0
cleanup() {
    systemctl stop anonguard.service || true
    dpkg --purge anonguard || true
    if [[ "$state_created" == 1 ]]; then rm -rf /var/lib/anonguard; fi
    rm -rf "$fixture_root"
}
trap cleanup EXIT
dependencies=$(dpkg-deb --field "$1" Depends)
[[ "$dependencies" == *libc6* && "$dependencies" == *libgcc-s1* ]]
[[ "$dependencies" == *'python3 (>= 3.11)'* ]]
dpkg --install "$1"
test "$(stat -c '%a:%u:%g' /etc/anonguard/runtime.env)" = '640:0:0'
test "$(stat -c '%a:%u:%g' /usr/bin/anonguard-daemon)" = '755:0:0'
test "$(stat -c '%a:%u:%g' /usr/bin/anonguard-run-app)" = '755:0:0'
test "$(stat -c '%a:%u:%g' /usr/bin/anonguard-pt)" = '755:0:0'
test -x /usr/bin/anonguard-onboard
/usr/bin/python3 -B /usr/bin/anonguard-onboard --help >/dev/null
test -x /usr/bin/anonguard-check-browser
/usr/bin/python3 -B /usr/bin/anonguard-check-browser --help >/dev/null
test -x /usr/bin/anonguard-setup
test -x /usr/bin/anonguard-native-adapter
test -r /usr/lib/sysusers.d/anonguard-native.conf
test -r /usr/share/doc/anonguard/docs/NATIVE_INSTALLATION.md
test -r /lib/systemd/system/anonguard-pt@.service
test -r /usr/share/doc/anonguard/docs/PLUGGABLE_TRANSPORT.md
test "$(stat -c '%a:%u:%g' /usr/share/doc/anonguard/anonguard-bwrap.apparmor)" = '644:0:0'
test -r /usr/share/doc/anonguard/docs/LINUX_APP_CONTAINMENT.md
test -r /usr/share/doc/anonguard/docs/FYP_DELIVERY.md
test -r /usr/share/doc/anonguard/LICENSE-MIT
test -r /usr/share/doc/anonguard/LICENSE-APACHE
python3 /usr/share/doc/anonguard/deployment_preflight.py --profile gateway
for setting in MemoryHigh=768M MemoryMax=1G MemorySwapMax=0 TasksMax=256 CPUQuota=200% LimitCORE=0; do
    grep -qx "$setting" /lib/systemd/system/anonguard.service
done
test ! -e /etc/apparmor.d/anonguard-bwrap
systemd-analyze verify /lib/systemd/system/anonguard.service
test -f /usr/share/applications/anonguard-setup.desktop
test -f /usr/share/applications/anonguard-browser.desktop
test -f /usr/share/doc/anonguard/browser-isolation/isolation.js
test ! -e /usr/share/anonguard/browser/isolation-signed.xpi
if systemctl is-active --quiet anonguard.service; then
    echo 'Unconfigured package unexpectedly started a service' >&2
    exit 1
fi
printf '\n# Package lifecycle preservation marker\n' >> /etc/anonguard/runtime.env
before=$(sha256sum /etc/anonguard/runtime.env)
dpkg --install "$1"
test "$(sha256sum /etc/anonguard/runtime.env)" = "$before"
# Distinct Debian versions exercise real upgrade/downgrade maintainer-script paths.
# The higher version is a clearly synthetic fixture of the SAME tested payload:
# this proves package/state lifecycle, not cross-protocol compatibility.
original_version=$(dpkg-deb --field "$1" Version)
upgrade_version="${original_version}+ci.1"
dpkg --compare-versions "$upgrade_version" gt "$original_version"
dpkg-deb --raw-extract "$1" "$fixture_root/upgrade"
python3 - "$fixture_root/upgrade/DEBIAN/control" "$upgrade_version" <<'PYCONTROL'
from pathlib import Path
import sys
path = Path(sys.argv[1])
lines = path.read_text().splitlines()
assert sum(line.startswith('Version: ') for line in lines) == 1
path.write_text('\n'.join('Version: ' + sys.argv[2] if line.startswith('Version: ') else line
                          for line in lines) + '\n')
PYCONTROL
dpkg-deb --build --root-owner-group "$fixture_root/upgrade" "$fixture_root/upgraded.deb"
mkdir -m 700 /var/lib/anonguard
state_created=1
/usr/bin/anonguard-daemon --initialize-identity --identity-key-path /var/lib/anonguard/identity.key > "$fixture_root/identity-public.json"
test "$(stat -c '%s:%a' /var/lib/anonguard/identity.key)" = '72:600'
# Opaque journal fixtures test byte preservation only; no daemon accepts these as votes.
for journal in guards.json identity.votes.json guards.consensus.json retirement.accepted.json; do
    printf '{"protocol_version":6,"fixture":"preserve-byte-for-byte"}\n' > "/var/lib/anonguard/$journal"
    chmod 600 "/var/lib/anonguard/$journal"
done
sha256sum /var/lib/anonguard/* > "$fixture_root/persistent.sha256"
for package in "$fixture_root/upgraded.deb" "$1"; do
    dpkg --install "$package"
    test "$(dpkg-query -W -f='${Version}' anonguard)" = "$(dpkg-deb --field "$package" Version)"
    test "$(sha256sum /etc/anonguard/runtime.env)" = "$before"
    sha256sum --check "$fixture_root/persistent.sha256"
    /usr/bin/anonguard-daemon --initialize-identity --identity-key-path /var/lib/anonguard/identity.key > "$fixture_root/public-after.json"
    cmp "$fixture_root/identity-public.json" "$fixture_root/public-after.json"
    if systemctl is-active --quiet anonguard.service; then
        echo 'Unaccepted upgrade unexpectedly started a service' >&2
        exit 1
    fi
done
dpkg --remove anonguard
test -f /etc/anonguard/runtime.env
test ! -e /usr/bin/anonguard-daemon
test ! -e /usr/bin/anonguard-run-app
dpkg --install "$1"
test "$(sha256sum /etc/anonguard/runtime.env)" = "$before"
dpkg --purge anonguard
test ! -e /etc/anonguard/runtime.env
test ! -e /lib/systemd/system/anonguard.service
sha256sum --check "$fixture_root/persistent.sha256"
rm -rf /var/lib/anonguard
state_created=0
rm -rf "$fixture_root"
trap - EXIT
echo 'Package install, synthetic-version upgrade/downgrade, persistent state, remove, recovery and purge checks passed'
