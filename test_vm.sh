#!/usr/bin/expect -f
# SSH into VM and run comprehensive AnonGuard tests

set timeout 300
set host "127.0.0.1"
set port "2222"
set user "user"
set pass "1234"

spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $port $user@$host

expect {
    "password:" { send "$pass\r" }
    timeout { puts "SSH connection timed out"; exit 1 }
}

expect "$ "

# ==========================================
# PHASE 1: Environment Check
# ==========================================
send "echo '========== PHASE 1: ENVIRONMENT CHECK =========='\r"
expect "$ "

send "uname -a\r"
expect "$ "

send "rustc --version 2>&1 && cargo --version 2>&1\r"
expect "$ "

send "python3 --version 2>&1\r"
expect "$ "

send "pip3 --version 2>&1\r"
expect "$ "

# ==========================================
# PHASE 2: Check if AnonGuard project exists on VM
# ==========================================
send "echo '========== PHASE 2: LOCATE PROJECT =========='\r"
expect "$ "

send "find /home -maxdepth 4 -name 'Cargo.toml' -path '*nonguard*' -o -name 'Cargo.toml' -path '*AnonGuard*' 2>/dev/null\r"
expect "$ "

send "ls -la /home/user/AnonGuard/ 2>/dev/null || ls -la /home/user/anonguard/ 2>/dev/null || echo 'PROJECT_NOT_ON_VM'\r"
expect "$ "

# ==========================================
# PHASE 3: Cargo Build (Debug)
# ==========================================
send "echo '========== PHASE 3: CARGO BUILD =========='\r"
expect "$ "

send "cd /home/user/AnonGuard 2>/dev/null || cd /home/user/anonguard 2>/dev/null || echo 'CANNOT_CD'\r"
expect "$ "

send "pwd\r"
expect "$ "

send "cargo build 2>&1 | tail -20\r"
expect {
    "$ " {}
    timeout { puts "Build timed out after 300s" }
}

# ==========================================
# PHASE 4: Cargo Test (Unit Tests)
# ==========================================
send "echo '========== PHASE 4: CARGO TEST =========='\r"
expect "$ "

send "cargo test 2>&1\r"
expect {
    "$ " {}
    timeout { puts "Tests timed out after 300s" }
}

# ==========================================
# PHASE 5: Release Build
# ==========================================
send "echo '========== PHASE 5: CARGO BUILD --release =========='\r"
expect "$ "

send "cargo build --release 2>&1 | tail -10\r"
expect {
    "$ " {}
    timeout { puts "Release build timed out" }
}

# ==========================================
# PHASE 6: Binary Check
# ==========================================
send "echo '========== PHASE 6: BINARY CHECK =========='\r"
expect "$ "

send "ls -lh target/debug/anonguard-daemon 2>/dev/null && echo 'DEBUG_BINARY_OK' || echo 'DEBUG_BINARY_MISSING'\r"
expect "$ "

send "ls -lh target/release/anonguard-daemon 2>/dev/null && echo 'RELEASE_BINARY_OK' || echo 'RELEASE_BINARY_MISSING'\r"
expect "$ "

send "./target/release/anonguard-daemon --help 2>&1 || echo 'BINARY_EXEC_FAILED'\r"
expect "$ "

# ==========================================
# PHASE 7: Python SDK
# ==========================================
send "echo '========== PHASE 7: PYTHON SDK =========='\r"
expect "$ "

send "pip3 install -e . 2>&1 | tail -10\r"
expect {
    "$ " {}
    timeout { puts "pip install timed out" }
}

send "python3 -c 'from anonguard import AnonGuard, GuardConfig; print(\"PYTHON_IMPORT_OK\"); g = AnonGuard(proxies=\[\"socks5://127.0.0.1:9050\"\], config=GuardConfig(strict=True, enable_jitter=True)); print(\"PYTHON_INIT_OK\")' 2>&1\r"
expect "$ "

# ==========================================
# PHASE 8: Research Benchmarks Check
# ==========================================
send "echo '========== PHASE 8: RESEARCH BENCHMARKS =========='\r"
expect "$ "

send "ls -la research_benchmarks/ 2>/dev/null\r"
expect "$ "

send "python3 research_benchmarks/packet_verifier.py --help 2>&1 | head -20 || echo 'PACKET_VERIFIER_FAILED'\r"
expect "$ "

# ==========================================
# PHASE 9: Docker / Network Services Check
# ==========================================
send "echo '========== PHASE 9: DOCKER & NETWORK =========='\r"
expect "$ "

send "docker ps 2>&1\r"
expect "$ "

send "ss -tlnp 2>&1 | head -20\r"
expect "$ "

# ==========================================
# DONE
# ==========================================
send "echo '========== ALL TESTS COMPLETE =========='\r"
expect "$ "

send "exit\r"
expect eof
