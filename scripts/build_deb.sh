#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "${ROOT_DIR}/Cargo.toml" | head -n 1)"
ARCH="$(dpkg --print-architecture)"
PKG_NAME="anonguard"
DIST_DIR="${ROOT_DIR}/dist"
STAGING_DIR="${ROOT_DIR}/target/deb_staging"

echo "[*] Preparing AnonGuard release binary..."
cd "${ROOT_DIR}"
case "${1:-}" in
    "") cargo build --locked --release ;;
    --prebuilt) ;;
    *) echo "Usage: $0 [--prebuilt]" >&2; exit 2 ;;
esac
if [ "$#" -gt 1 ] || [ ! -x "${ROOT_DIR}/target/release/anonguard-daemon" ] || [ ! -x "${ROOT_DIR}/target/release/anonguard-identity-policy" ]; then
    echo "Expected daemon and identity-policy release binaries and at most one option" >&2
    exit 2
fi

echo "[*] Preparing Debian package filesystem layout..."
rm -rf "${STAGING_DIR}"
mkdir -p "${STAGING_DIR}/DEBIAN"
mkdir -p "${STAGING_DIR}/usr/bin"
mkdir -p "${STAGING_DIR}/lib/systemd/system"
mkdir -p "${STAGING_DIR}/etc/anonguard"
mkdir -p "${STAGING_DIR}/usr/share/doc/anonguard"
mkdir -p "${DIST_DIR}"
find "${STAGING_DIR}" -type d -exec chmod 755 {} +

# 1. Binary
cp "${ROOT_DIR}/target/release/anonguard-daemon" "${STAGING_DIR}/usr/bin/anonguard-daemon"
chmod 755 "${STAGING_DIR}/usr/bin/anonguard-daemon"
cp "${ROOT_DIR}/target/release/anonguard-identity-policy" "${STAGING_DIR}/usr/bin/anonguard-identity-policy"
chmod 755 "${STAGING_DIR}/usr/bin/anonguard-identity-policy"
cp "${ROOT_DIR}/scripts/anonguard_run_app.py" "${STAGING_DIR}/usr/bin/anonguard-run-app"
chmod 755 "${STAGING_DIR}/usr/bin/anonguard-run-app"
cp "${ROOT_DIR}/scripts/pt_supervisor.py" "${STAGING_DIR}/usr/bin/anonguard-pt"
chmod 755 "${STAGING_DIR}/usr/bin/anonguard-pt"
cp "${ROOT_DIR}/scripts/browser_session.py" "${STAGING_DIR}/usr/bin/anonguard-browser"
chmod 755 "${STAGING_DIR}/usr/bin/anonguard-browser"

cp "${ROOT_DIR}/scripts/device_setup.py" "${STAGING_DIR}/usr/bin/anonguard-setup"
cp "${ROOT_DIR}/scripts/native_adapter.py" "${STAGING_DIR}/usr/bin/anonguard-native-adapter"
chmod 755 "${STAGING_DIR}/usr/bin/anonguard-setup" "${STAGING_DIR}/usr/bin/anonguard-native-adapter"
install -d -m 755 "${STAGING_DIR}/usr/lib" "${STAGING_DIR}/usr/lib/sysusers.d"
cp "${ROOT_DIR}/contrib/anonguard-native.conf" "${STAGING_DIR}/usr/lib/sysusers.d/anonguard-native.conf"
chmod 644 "${STAGING_DIR}/usr/lib/sysusers.d/anonguard-native.conf"

# Ship reviewable extension sources; never install an unsigned extension as active.
install -d -m 755 "${STAGING_DIR}/usr/share/doc/anonguard/browser-isolation"
for source in manifest.json isolation.js background.js; do
    install -m 644 "${ROOT_DIR}/browser/isolation/${source}" "${STAGING_DIR}/usr/share/doc/anonguard/browser-isolation/${source}"
done

# Derive minimum library versions from the actual packaged ELF, rather than
# guessing a libc baseline or allowing installation without its dependencies.
DEPS_DIR="${ROOT_DIR}/target/deb_dependencies"
mkdir -p "${DEPS_DIR}/debian"
cat << EOF > "${DEPS_DIR}/debian/control"
Source: ${PKG_NAME}
Section: net
Priority: optional
Maintainer: Muhammad Umar Shahzad <Un-9oon@users.noreply.github.com>

Package: ${PKG_NAME}
Architecture: any
Description: Experimental anonymity transport
EOF
SHLIBS_OUTPUT="$(cd "${DEPS_DIR}" && dpkg-shlibdeps -O -e"${STAGING_DIR}/usr/bin/anonguard-daemon")"
SHLIBS_DEPENDS="$(printf '%s\n' "${SHLIBS_OUTPUT}" | sed -n 's/^shlibs:Depends=//p')"
if [ -z "${SHLIBS_DEPENDS}" ]; then
    echo 'No runtime library dependencies detected; refusing an incomplete Debian package' >&2
    exit 1
fi

# 2. Systemd service
cp "${ROOT_DIR}/contrib/anonguard.service" "${STAGING_DIR}/lib/systemd/system/anonguard.service"
chmod 644 "${STAGING_DIR}/lib/systemd/system/anonguard.service"
cp "${ROOT_DIR}/contrib/anonguard-pt@.service" "${STAGING_DIR}/lib/systemd/system/anonguard-pt@.service"
chmod 644 "${STAGING_DIR}/lib/systemd/system/anonguard-pt@.service"

# 3. Default configuration
cp "${ROOT_DIR}/contrib/runtime.env" "${STAGING_DIR}/etc/anonguard/runtime.env"
chmod 640 "${STAGING_DIR}/etc/anonguard/runtime.env"
printf '/etc/anonguard/runtime.env\n' > "${STAGING_DIR}/DEBIAN/conffiles"

# 4. Documentation and explicit administrator policy examples (never auto-loaded).
cp "${ROOT_DIR}/scripts/deployment_preflight.py" "${STAGING_DIR}/usr/share/doc/anonguard/deployment_preflight.py"
cp "${ROOT_DIR}/scripts/vm_profile.py" "${STAGING_DIR}/usr/share/doc/anonguard/vm_profile.py"
chmod 644 "${STAGING_DIR}/usr/share/doc/anonguard/vm_profile.py"
chmod 644 "${STAGING_DIR}/usr/share/doc/anonguard/deployment_preflight.py"
cp "${ROOT_DIR}/scripts/verify_release.py" "${STAGING_DIR}/usr/share/doc/anonguard/verify_release.py"
chmod 644 "${STAGING_DIR}/usr/share/doc/anonguard/verify_release.py"
mkdir -p "${STAGING_DIR}/usr/share/doc/anonguard/docs"
chmod 755 "${STAGING_DIR}/usr/share/doc/anonguard/docs"
cp "${ROOT_DIR}/docs/"*.md "${STAGING_DIR}/usr/share/doc/anonguard/docs/"
cp "${ROOT_DIR}/docs/design/PLUGGABLE_TRANSPORT.md" "${STAGING_DIR}/usr/share/doc/anonguard/docs/"
cp "${ROOT_DIR}/deploy/apparmor/anonguard-bwrap" "${STAGING_DIR}/usr/share/doc/anonguard/anonguard-bwrap.apparmor"
chmod 644 "${STAGING_DIR}/usr/share/doc/anonguard/docs/"*.md "${STAGING_DIR}/usr/share/doc/anonguard/anonguard-bwrap.apparmor"
cp "${ROOT_DIR}/README.md" "${STAGING_DIR}/usr/share/doc/anonguard/README.md"
chmod 644 "${STAGING_DIR}/usr/share/doc/anonguard/README.md"

cat << 'EOF' > "${STAGING_DIR}/usr/share/doc/anonguard/copyright"
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: anonguard
Source: https://github.com/Un-9oon/AnonGuard

Files: *
Copyright: 2026 AnonGuard Research Group
License: MIT or Apache-2.0
EOF
chmod 644 "${STAGING_DIR}/usr/share/doc/anonguard/copyright"

cp "${ROOT_DIR}/LICENSE-MIT" "${ROOT_DIR}/LICENSE-APACHE" "${STAGING_DIR}/usr/share/doc/anonguard/"
chmod 644 "${STAGING_DIR}/usr/share/doc/anonguard/"LICENSE-*

cp "${ROOT_DIR}/scripts/latency_profile.py" "${STAGING_DIR}/usr/share/doc/anonguard/latency_profile.py"
chmod 644 "${STAGING_DIR}/usr/share/doc/anonguard/latency_profile.py"

# 5. DEBIAN control file
cat << EOF > "${STAGING_DIR}/DEBIAN/control"
Package: ${PKG_NAME}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Depends: ${SHLIBS_DEPENDS}
Suggests: iproute2, nftables, bubblewrap, python3, libseccomp2, util-linux, obfs4proxy
Maintainer: Muhammad Umar Shahzad <Un-9oon@users.noreply.github.com>
Homepage: https://github.com/Un-9oon/AnonGuard
Description: Experimental authenticated multihop anonymity transport
 AnonGuard provides pinned relay links, layered circuits and optional Linux
 application namespace isolation. Production anonymity and resistance to
 traffic correlation have not been independently established.
EOF
chmod 644 "${STAGING_DIR}/DEBIAN/control"

# 6. DEBIAN postinst script
cat << 'EOF' > "${STAGING_DIR}/DEBIAN/postinst"
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
exit 0
EOF
chmod 755 "${STAGING_DIR}/DEBIAN/postinst"

# 7. DEBIAN prerm script
cat << 'EOF' > "${STAGING_DIR}/DEBIAN/prerm"
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl stop anonguard-native-adapter.service anonguard-client.service anonguard-relay.service 2>/dev/null || true
    # Preserve native firewall restrictions after package removal.
    systemctl stop anonguard.service 2>/dev/null || true
    systemctl stop 'anonguard-pt@*.service' 2>/dev/null || true
fi
exit 0
EOF
chmod 755 "${STAGING_DIR}/DEBIAN/prerm"

# 8. Build Debian Package
OUTPUT_DEB="${DIST_DIR}/${PKG_NAME}_${VERSION}_${ARCH}.deb"
echo "[*] Packaging with dpkg-deb into ${OUTPUT_DEB}..."
dpkg-deb --build --root-owner-group "${STAGING_DIR}" "${OUTPUT_DEB}"

echo "[✓] Successfully built Debian package: ${OUTPUT_DEB}"
ls -lh "${OUTPUT_DEB}"
