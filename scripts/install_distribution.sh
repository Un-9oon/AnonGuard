#!/usr/bin/env bash
# Run from an extracted, independently authenticated AnonGuard distribution.
set -euo pipefail
case "${1:-}" in
  --check) check_only=1 ;;
  '') check_only=0 ;;
  *) echo 'Usage: ./install.sh [--check]' >&2; exit 2 ;;
esac
[[ $# -le 1 ]] || exit 2
bundle_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$bundle_dir"
for tool in sha256sum dpkg dpkg-deb apt-get python3; do
  command -v "$tool" >/dev/null || { echo "Required system tool missing: $tool" >&2; exit 1; }
done
[[ -f SHA256SUMS && ! -L SHA256SUMS ]] || { echo 'Distribution checksum manifest missing.' >&2; exit 1; }
sha256sum --check --strict SHA256SUMS
shopt -s nullglob
packages=(anonguard_*.deb)
[[ ${#packages[@]} == 1 && ! -L "${packages[0]}" ]] || { echo 'Expected exactly one regular AnonGuard package.' >&2; exit 1; }
package_path="$bundle_dir/${packages[0]}"
[[ "$(dpkg-deb -f "$package_path" Package)" == anonguard ]] || exit 1
[[ "$(dpkg-deb -f "$package_path" Architecture)" == "$(dpkg --print-architecture)" ]] || {
  echo 'This package is for a different CPU architecture.' >&2; exit 1;
}
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || {
  echo 'Python 3.11 or later is required.' >&2; exit 1;
}
echo 'Checking system dependencies without installing or starting anything...'
apt-get --simulate install "$package_path"
if [[ "$check_only" == 1 ]]; then
  echo 'Package dependency check completed. Network/browser readiness has not been verified.'
  exit 0
fi
[[ "$EUID" != 0 ]] || { echo 'Run ./install.sh as your ordinary desktop user; sudo is used only for installation.' >&2; exit 1; }
[[ -t 0 && -t 1 && -z "${SSH_CONNECTION:-}" && -z "${SSH_TTY:-}" ]] || {
  echo 'Run the installer in a terminal at the target computer, not through SSH.' >&2; exit 1;
}
[[ -d /run/systemd/system ]] || { echo 'A running Linux systemd installation is required.' >&2; exit 1; }
command -v sudo >/dev/null || { echo 'The system administrator must install sudo first.' >&2; exit 1; }
echo
echo 'AnonGuard is an experimental anonymity network application.'
echo 'Installation needs internet access to your configured OS repositories.'
echo 'Setup needs an operator-provided network profile. Browsing also needs supported Firefox ESR and an approved Mozilla-signed addon.'
echo 'The wizard may configure device-wide firewall restrictions. Use a dedicated test device and read QUICK_START.md first.'
read -r -p 'Install this package and open the setup wizard? [y/N] ' answer
[[ "$answer" == y || "$answer" == Y ]] || exit 0
sudo /usr/bin/apt-get install "$package_path"
echo 'Package installed. Opening Client / Volunteer setup as your ordinary user.'
exec /usr/bin/anonguard-onboard --start
