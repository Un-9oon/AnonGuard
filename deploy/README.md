# Native Deployment Guide (Forensic Hardening)

This guide covers deploying AnonGuard directly onto a hardened Linux system (bare-metal or VM) utilizing `systemd` to achieve maximum forensic protection and network stack camouflage.

## Prerequisites
- A Linux host with `systemd` (e.g., Debian/Ubuntu server).
- Root access.

## Deployment Steps

1. **Build the binary:**
   Ensure you have Rust installed, then compile AnonGuard for release.
   ```bash
   cargo build --release
   ```

2. **Install the binary:**
   Copy the binary to the system path.
   ```bash
   sudo cp target/release/anonguard-daemon /usr/local/bin/
   sudo chmod +x /usr/local/bin/anonguard-daemon
   ```

3. **Create the unprivileged service user:**
   AnonGuard should never run as root.
   ```bash
   sudo useradd -r -s /bin/false anonguard
   ```

4. **Install the `systemd` service:**
   Copy the provided `anonguard.service` configuration file to the systemd directory.
   ```bash
   sudo cp deploy/anonguard.service /etc/systemd/system/
   ```

5. **Customize Role (Optional):**
   By default, the service is configured to run as an `exit` node on port `9050`. To change this, edit the `ExecStart` line in `/etc/systemd/system/anonguard.service`:
   ```bash
   sudo nano /etc/systemd/system/anonguard.service
   ```

6. **Enable and start the service:**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable anonguard
   sudo systemctl start anonguard
   ```

## Why deploy natively?
- **Zero Network Fingerprinting:** No Docker NAT or bridge modifying your MTU/TTL packets, blending perfectly into normal internet traffic.
- **Forensic Protection:** The `systemd` configuration explicitly drops privileges, strictly isolates the filesystem (`ProtectSystem=strict`), and routes stdout/stderr to `/dev/null` preventing JSON log accumulation on disk.
