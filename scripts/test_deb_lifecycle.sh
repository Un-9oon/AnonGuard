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
dpkg --install "$1"
test "$(stat -c '%a:%u:%g' /etc/anonguard/runtime.env)" = '640:0:0'
test "$(stat -c '%a:%u:%g' /usr/bin/anonguard-daemon)" = '755:0:0'
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
dpkg --install "$1"
test "$(sha256sum /etc/anonguard/runtime.env)" = "$before"
dpkg --purge anonguard
test ! -e /etc/anonguard/runtime.env
test ! -e /lib/systemd/system/anonguard.service
trap - EXIT
echo 'Package install, reinstall, remove, recovery and purge checks passed'
