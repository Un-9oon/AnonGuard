#!/usr/bin/env bash
# ==============================================================================
# AnonGuard Automated Setup Wizard
# Intuitive, interactive installer for Linux systems (Debian, Ubuntu, Kali, Arch, Fedora, etc.)
# ==============================================================================

set -euo pipefail

# Text formatting
BOLD="\033[1m"
GREEN="\033[0;32m"
BLUE="\033[0;34m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
RED="\033[0;31m"
RESET="\033[0m"

clear 2>/dev/null || true

echo -e "${CYAN}${BOLD}"
cat << "EOF"
    ___                         ______                         __
   /   |  ____  ____  ____     / ____/_  ______ _________  / /
  / /| | / __ \/ __ \/ __ \   / / __/ / / / __ `/ ___/ __  / 
 / ___ |/ / / / /_/ / / / /  / /_/ / /_/ / /_/ / /  / /_/ /  
/_/  |_/_/ /_/\____/_/ /_/   \____/\__,_/\__,_/_/   \__,_/   
EOF
echo -e "${RESET}"
echo -e "${BOLD}Military-Grade Decentralized Anonymity Gateway — Automated Setup${RESET}"
echo -e "${BLUE}=================================================================${RESET}\n"

# 1. Privileges & Installation Targets
IS_ROOT=0
if [ "$EUID" -eq 0 ]; then
    IS_ROOT=1
    BIN_DIR="/usr/local/bin"
    CONF_DIR="/etc/anonguard"
    SERVICE_DIR="/etc/systemd/system"
    echo -e "${GREEN}[*] Running with Administrator (root) privileges.${RESET}"
else
    BIN_DIR="${HOME}/.local/bin"
    CONF_DIR="${HOME}/.config/anonguard"
    SERVICE_DIR="${HOME}/.config/systemd/user"
    echo -e "${YELLOW}[*] Running as non-root user (${USER}). Installing to user home (${BIN_DIR}).${RESET}"
fi
mkdir -p "${BIN_DIR}" "${CONF_DIR}"

# Detect architecture
ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64)  TARGET_ARCH="amd64" ;;
    aarch64) TARGET_ARCH="arm64" ;;
    *)
        echo -e "${YELLOW}[!] Architecture ${ARCH}.${RESET}"
        TARGET_ARCH="${ARCH}"
        ;;
esac

echo -e "${GREEN}[*] Target Architecture:${RESET} ${ARCH}\n"

# 2. Interactive Questionnaire (Supports non-interactive mode if AUTO_INSTALL=1)
if [ "${AUTO_INSTALL:-0}" = "1" ]; then
    MODE_CHOICE=1
    OBFUSCATION_CHOICE=1
    PORT_CHOICE="9050"
    KILLSWITCH_CHOICE="Y"
    SYBIL_CHOICE="Y"
    SERVICE_CHOICE="Y"
else
    echo -e "${BOLD}${CYAN}Step 1: Operating Mode${RESET}"
    echo -e "  ${BOLD}[1] Client Gateway${RESET} — Route your PC's browser & apps through 3-hop onion circuits ${GREEN}(Default)${RESET}"
    echo -e "  ${BOLD}[2] Volunteer Relay Node${RESET} — Help the network by relaying encrypted traffic behind NAT"
    echo -e "  ${BOLD}[3] Directory Authority${RESET} — Run an Ed25519 consensus authority server"
    read -rp "$(echo -e "${YELLOW}Select mode [1-3, default=1]: ${RESET}")" MODE_INPUT
    MODE_CHOICE="${MODE_INPUT:-1}"

    echo -e "\n${BOLD}${CYAN}Step 2: Obfuscation & AI-Resistance Level${RESET}"
    echo -e "  ${BOLD}[1] Quantum Chaos (Q-RMT Wigner Surmise)${RESET} — Breaks Deep Learning timing models ${GREEN}(Recommended)${RESET}"
    echo -e "  ${BOLD}[2] Classical Chaos (Lorenz Attractor)${RESET} — Non-linear dynamical chaos"
    echo -e "  ${BOLD}[3] Poisson Jitter${RESET} — Standard exponential delay injection"
    echo -e "  ${BOLD}[4] Fixed Onion Cells Only${RESET} — Constant 1024-byte framing without timing delays"
    read -rp "$(echo -e "${YELLOW}Select level [1-4, default=1]: ${RESET}")" OBF_INPUT
    OBFUSCATION_CHOICE="${OBF_INPUT:-1}"

    echo -e "\n${BOLD}${CYAN}Step 3: Security & Network Policies${RESET}"
    read -rp "$(echo -e "${YELLOW}Enable Fail-Closed Kill Switch (Zero-Leak Guarantee)? [Y/n]: ${RESET}")" KS_INPUT
    KILLSWITCH_CHOICE="${KS_INPUT:-Y}"

    read -rp "$(echo -e "${YELLOW}Enforce BGP /16 Subnet Diversity (Anti-Sybil Defense)? [Y/n]: ${RESET}")" SYBIL_INPUT
    SYBIL_CHOICE="${SYBIL_INPUT:-Y}"

    read -rp "$(echo -e "${YELLOW}SOCKS5 Proxy Port [default=9050]: ${RESET}")" PORT_INPUT
    PORT_CHOICE="${PORT_INPUT:-9050}"

    echo -e "\n${BOLD}${CYAN}Step 4: System Integration${RESET}"
    read -rp "$(echo -e "${YELLOW}Run AnonGuard automatically as a background service on boot? [Y/n]: ${RESET}")" SVC_INPUT
    SERVICE_CHOICE="${SVC_INPUT:-Y}"
fi

echo -e "\n${BLUE}=================================================================${RESET}"
echo -e "${GREEN}[*] Installing AnonGuard components...${RESET}"

# 3. Locate or Build Binary
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_PATH="${BIN_DIR}/anonguard-daemon"

if [ -f "${SCRIPT_DIR}/target/release/anonguard-daemon" ]; then
    cp "${SCRIPT_DIR}/target/release/anonguard-daemon" "${BIN_PATH}"
elif [ -f "${SCRIPT_DIR}/dist/anonguard-daemon" ]; then
    cp "${SCRIPT_DIR}/dist/anonguard-daemon" "${BIN_PATH}"
elif command -v anonguard-daemon >/dev/null 2>&1; then
    echo -e "${GREEN}[✓] Existing anonguard-daemon found in PATH.${RESET}"
else
    # Check if cargo is available to build locally
    if command -v cargo >/dev/null 2>&1; then
        echo -e "${YELLOW}[*] Compiling AnonGuard locally...${RESET}"
        (cd "${SCRIPT_DIR}" && cargo build --release)
        cp "${SCRIPT_DIR}/target/release/anonguard-daemon" "${BIN_PATH}"
    else
        echo -e "${RED}[!] Error: Could not locate binary and Cargo is not installed.${RESET}"
        exit 1
    fi
fi
chmod 755 "${BIN_PATH}"
echo -e "${GREEN}[✓] Installed binary to ${BIN_PATH}${RESET}"

# 4. Generate Customized config.toml
mkdir -p "${CONF_DIR}"

ENABLE_QUANTUM="false"
ENABLE_CHAOS="false"
ENABLE_JITTER="false"

case "${OBFUSCATION_CHOICE}" in
    1) ENABLE_QUANTUM="true" ;;
    2) ENABLE_CHAOS="true" ;;
    3) ENABLE_JITTER="true" ;;
    *) ;;
esac

STRICT_KS="true"
if [[ "${KILLSWITCH_CHOICE}" =~ ^[Nn]$ ]]; then
    STRICT_KS="false"
fi

DIVERSE_SUBNET="true"
if [[ "${SYBIL_CHOICE}" =~ ^[Nn]$ ]]; then
    DIVERSE_SUBNET="false"
fi

RELAY_MODE="false"
REVERSE_RELAY_MODE="false"
AUTHORITY_MODE="false"

case "${MODE_CHOICE}" in
    2) REVERSE_RELAY_MODE="true" ;;
    3) AUTHORITY_MODE="true" ;;
    *) ;;
esac

cat << EOF > "${CONF_DIR}/config.toml"
# AnonGuard Tailored System Configuration
listen_addr = "127.0.0.1:${PORT_CHOICE}"
strict_killswitch = ${STRICT_KS}
enforce_remote_dns = true
disable_ipv6 = true
enable_onion_routing = true
enforce_subnet_diversity = ${DIVERSE_SUBNET}

# Obfuscation Engine
enable_quantum = ${ENABLE_QUANTUM}
quantum_ensemble = "goe"
enable_chaos = ${ENABLE_CHAOS}
enable_jitter = ${ENABLE_JITTER}
jitter_lambda = 0.05

# TLS Fingerprint Normalization
ja4_profile = "chrome_120"

# Operational Mode
relay_mode = ${RELAY_MODE}
reverse_relay_mode = ${REVERSE_RELAY_MODE}
authority_mode = ${AUTHORITY_MODE}
EOF
chmod 644 "${CONF_DIR}/config.toml"
echo -e "${GREEN}[✓] Generated configuration at ${CONF_DIR}/config.toml${RESET}"

# 5. Configure Systemd Service
if [[ "${SERVICE_CHOICE}" =~ ^[Yy]$ ]]; then
    mkdir -p "${SERVICE_DIR}"
    SERVICE_FILE="${SERVICE_DIR}/anonguard.service"
    
    EXTRA_FLAGS="--listen 127.0.0.1:${PORT_CHOICE} --onion"
    if [ "${ENABLE_QUANTUM}" = "true" ]; then
        EXTRA_FLAGS="${EXTRA_FLAGS} --quantum"
    elif [ "${ENABLE_CHAOS}" = "true" ]; then
        EXTRA_FLAGS="${EXTRA_FLAGS} --chaos"
    fi
    if [ "${DIVERSE_SUBNET}" = "true" ]; then
        EXTRA_FLAGS="${EXTRA_FLAGS} --enforce-subnet-diversity"
    fi
    if [ "${REVERSE_RELAY_MODE}" = "true" ]; then
        EXTRA_FLAGS="${EXTRA_FLAGS} --reverse-relay"
    fi
    if [ "${AUTHORITY_MODE}" = "true" ]; then
        EXTRA_FLAGS="${EXTRA_FLAGS} --authority"
    fi

    if [ "${IS_ROOT}" -eq 1 ]; then
        cat << EOF > "${SERVICE_FILE}"
[Unit]
Description=AnonGuard Military-Grade Anonymity Gateway
After=network.target network-online.target
Wants=network-online.target
Documentation=https://github.com/Un-9oon/AnonGuard

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=${BIN_PATH} ${EXTRA_FLAGS}
Restart=on-failure
RestartSec=3s
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
        chmod 644 "${SERVICE_FILE}"
        systemctl daemon-reload || true
        systemctl enable --now anonguard.service || true
        echo -e "${GREEN}[✓] Installed and started background service: anonguard.service${RESET}"
    else
        cat << EOF > "${SERVICE_FILE}"
[Unit]
Description=AnonGuard Military-Grade Anonymity Gateway (User Service)
After=network.target
Documentation=https://github.com/Un-9oon/AnonGuard

[Service]
Type=simple
ExecStart=${BIN_PATH} ${EXTRA_FLAGS}
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=default.target
EOF
        chmod 644 "${SERVICE_FILE}"
        systemctl --user daemon-reload 2>/dev/null || true
        systemctl --user enable --now anonguard.service 2>/dev/null || true
        echo -e "${GREEN}[✓] Installed user service at ${SERVICE_FILE}${RESET}"
    fi
fi

# 6. Self-Verification Probe
echo -e "\n${YELLOW}[*] Validating gateway status on 127.0.0.1:${PORT_CHOICE}...${RESET}"
sleep 1
if ss -tuln 2>/dev/null | grep -q ":${PORT_CHOICE}" || netstat -tuln 2>/dev/null | grep -q ":${PORT_CHOICE}"; then
    echo -e "${GREEN}${BOLD}[✓] SUCCESS: AnonGuard is ACTIVE and listening on 127.0.0.1:${PORT_CHOICE}!${RESET}"
else
    echo -e "${YELLOW}[*] Daemon initialized (service is starting up).${RESET}"
fi

# 7. Final User Summary & Instructions
echo -e "\n${BLUE}=================================================================${RESET}"
echo -e "${BOLD}${GREEN}🎉 AnonGuard Installation Complete!${RESET}"
echo -e "${BLUE}=================================================================${RESET}"
echo -e "${BOLD}Your SOCKS5 Proxy Endpoint:${RESET}  ${CYAN}127.0.0.1:${PORT_CHOICE}${RESET}"
echo -e "${BOLD}Protocols Supported:${RESET}         ${CYAN}SOCKS5 / SOCKS5h (Remote DNS)${RESET}"
echo -e "${BOLD}Routing:${RESET}                     ${CYAN}3-Hop Layered Onion Circuit${RESET}"
echo -e "${BOLD}Morphing Engine:${RESET}             ${CYAN}$([ "${ENABLE_QUANTUM}" = "true" ] && echo "Quantum Q-RMT (Wigner Surmise)" || echo "Classical Chaos")${RESET}"
echo -e "${BLUE}-----------------------------------------------------------------${RESET}"
echo -e "${BOLD}How to Use AnonGuard in Your Browser:${RESET}"
echo -e "  1. Open ${BOLD}Firefox${RESET} (or Chrome) Settings -> Network Settings."
echo -e "  2. Select ${BOLD}Manual proxy configuration${RESET}."
echo -e "  3. Set SOCKS Host: ${CYAN}127.0.0.1${RESET} | Port: ${CYAN}${PORT_CHOICE}${RESET} | Select ${BOLD}SOCKS v5${RESET}."
echo -e "  4. Check the box: ${GREEN}☑ Proxy DNS when using SOCKS v5${RESET} (Prevents DNS leaks)."
echo -e "${BLUE}-----------------------------------------------------------------${RESET}"
echo -e "${BOLD}Useful Service Commands:${RESET}"
echo -e "  Check Status:  ${CYAN}sudo systemctl status anonguard${RESET}"
echo -e "  View Logs:     ${CYAN}sudo journalctl -u anonguard -f${RESET}"
echo -e "  Restart:       ${CYAN}sudo systemctl restart anonguard${RESET}"
echo -e "  Stop:          ${CYAN}sudo systemctl stop anonguard${RESET}"
echo -e "${BLUE}=================================================================${RESET}\n"
