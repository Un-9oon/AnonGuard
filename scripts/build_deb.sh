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
if [ "$#" -gt 1 ] || [ ! -x "${ROOT_DIR}/target/release/anonguard-daemon" ]; then
    echo "Expected one executable release binary and at most one option" >&2
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

# 2. Systemd service
cp "${ROOT_DIR}/contrib/anonguard.service" "${STAGING_DIR}/lib/systemd/system/anonguard.service"
chmod 644 "${STAGING_DIR}/lib/systemd/system/anonguard.service"

# 3. Default configuration
cp "${ROOT_DIR}/contrib/runtime.env" "${STAGING_DIR}/etc/anonguard/runtime.env"
chmod 640 "${STAGING_DIR}/etc/anonguard/runtime.env"
printf '/etc/anonguard/runtime.env\n' > "${STAGING_DIR}/DEBIAN/conffiles"

# 4. Documentation
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

# 5. DEBIAN control file
cat << EOF > "${STAGING_DIR}/DEBIAN/control"
Package: ${PKG_NAME}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: Muhammad Umar Shahzad <Un-9oon@users.noreply.github.com>
Homepage: https://github.com/Un-9oon/AnonGuard
Description: Experimental authenticated three-hop anonymity transport
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
    systemctl stop anonguard.service 2>/dev/null || true
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
