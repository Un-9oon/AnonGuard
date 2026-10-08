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
cleanup() {
    systemctl stop anonguard.service || true
    dpkg --purge anonguard || true
}
trap cleanup EXIT
dependencies=$(dpkg-deb --field "$1" Depends)
[[ "$dependencies" == *libc6* && "$dependencies" == *libgcc-s1* ]]
dpkg --install "$1"
test "$(stat -c '%a:%u:%g' /etc/anonguard/runtime.env)" = '640:0:0'
test "$(stat -c '%a:%u:%g' /usr/bin/anonguard-daemon)" = '755:0:0'
test "$(stat -c '%a:%u:%g' /usr/bin/anonguard-run-app)" = '755:0:0'
test "$(stat -c '%a:%u:%g' /usr/bin/anonguard-pt)" = '755:0:0'
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
if systemctl is-active --quiet anonguard.service; then
    echo 'Unconfigured package unexpectedly started a service' >&2
    exit 1
fi
printf '\n# Package lifecycle preservation marker\n' >> /etc/anonguard/runtime.env
before=$(sha256sum /etc/anonguard/runtime.env)
dpkg --install "$1"
test "$(sha256sum /etc/anonguard/runtime.env)" = "$before"
dpkg --remove anonguard
test -f /etc/anonguard/runtime.env
test ! -e /usr/bin/anonguard-daemon
test ! -e /usr/bin/anonguard-run-app
dpkg --install "$1"
test "$(sha256sum /etc/anonguard/runtime.env)" = "$before"
dpkg --purge anonguard
test ! -e /etc/anonguard/runtime.env
test ! -e /lib/systemd/system/anonguard.service
trap - EXIT
echo 'Package install, reinstall, remove, recovery and purge checks passed'
