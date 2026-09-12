<#
.SYNOPSIS
    AnonGuard Automated Setup Wizard for Windows.
    Interactive installer for non-technical users.
#>

[CmdletBinding()]
param()

Clear-Host

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "   AnonGuard Authenticated Anonymity Gateway - Windows Setup" -ForegroundColor Green
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host ""

# Determine target directory
$InstallDir = "$env:ProgramFiles\AnonGuard"
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    $InstallDir = "$env:LOCALAPPDATA\AnonGuard"
    Write-Host "[*] Note: Running without Administrator privileges. Installing to: $InstallDir" -ForegroundColor Yellow
} else {
    Write-Host "[*] Running with Administrator privileges. Installing to: $InstallDir" -ForegroundColor Green
}
Write-Host ""

# 1. Questionnaire
Write-Host "Step 1: Select Operating Mode" -ForegroundColor Cyan
Write-Host "  [1] Client Gateway (Maximum Privacy & Anonymity) [Default]"
Write-Host "  [2] Volunteer Relay Node (Help others route traffic)"
$ModeChoice = Read-Host "Select Mode [1-2, default=1]"
if ([string]::IsNullOrWhiteSpace($ModeChoice)) { $ModeChoice = "1" }

Write-Host ""
Write-Host "Step 2: Obfuscation Level" -ForegroundColor Cyan
Write-Host "  [1] Quantum Chaos (Q-RMT Wigner Surmise) [Recommended]"
Write-Host "  [2] Classical Chaos (Lorenz Attractor)"
$ObfChoice = Read-Host "Select Level [1-2, default=1]"
if ([string]::IsNullOrWhiteSpace($ObfChoice)) { $ObfChoice = "1" }

Write-Host ""
$Port = Read-Host "Enter SOCKS5 Proxy Port [default=9050]"
if ([string]::IsNullOrWhiteSpace($Port)) { $Port = "9050" }

Write-Host ""
$StartOnLogin = Read-Host "Launch AnonGuard automatically when Windows starts? [Y/n]"
if ([string]::IsNullOrWhiteSpace($StartOnLogin)) { $StartOnLogin = "Y" }

# 2. Directory Creation & File Copy
Write-Host ""
Write-Host "[*] Installing AnonGuard..." -ForegroundColor Yellow
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

$CurrentDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ExeSource = Join-Path $CurrentDir "anonguard-daemon.exe"
if (-not (Test-Path $ExeSource)) {
    $ExeSource = Join-Path $CurrentDir "target\release\anonguard-daemon.exe"
}

if (Test-Path $ExeSource) {
    Copy-Item $ExeSource (Join-Path $InstallDir "anonguard-daemon.exe") -Force
    Write-Host "[✓] Installed anonguard-daemon.exe" -ForegroundColor Green
} else {
    Write-Host "[!] Warning: anonguard-daemon.exe not found in installer directory." -ForegroundColor Yellow
}

# 3. Generate config.toml
$QuantumFlag = if ($ObfChoice -eq "1") { "true" } else { "false" }
$ChaosFlag = if ($ObfChoice -eq "2") { "true" } else { "false" }

$ConfigContent = @"
# AnonGuard Windows Configuration
listen_addr = "127.0.0.1:$Port"
strict_killswitch = true
enforce_remote_dns = true
disable_ipv6 = true
enable_onion_routing = true
enforce_subnet_diversity = true
enable_quantum = $QuantumFlag
quantum_ensemble = "goe"
enable_chaos = $ChaosFlag
ja4_profile = "chrome_120"
"@

Set-Content -Path (Join-Path $InstallDir "config.toml") -Value $ConfigContent
Write-Host "[✓] Generated config.toml" -ForegroundColor Green

# 4. Windows Startup Integration
if ($StartOnLogin -match "^[Yy]") {
    $WshShell = New-Object -ComObject WScript.Shell
    $StartupFolder = [Environment]::GetFolderPath("Startup")
    $Shortcut = $WshShell.CreateShortcut((Join-Path $StartupFolder "AnonGuard.lnk"))
    $Shortcut.TargetPath = (Join-Path $InstallDir "anonguard-daemon.exe")
    $Shortcut.Arguments = "--listen 127.0.0.1:$Port --onion"
    if ($QuantumFlag -eq "true") { $Shortcut.Arguments += " --quantum" }
    $Shortcut.WorkingDirectory = $InstallDir
    $Shortcut.WindowStyle = 7 # Minimized
    $Shortcut.Save()
    Write-Host "[✓] Added AnonGuard to Windows Startup folder" -ForegroundColor Green
}

# 5. Desktop Shortcut
$WshShell = New-Object -ComObject WScript.Shell
$DesktopFolder = [Environment]::GetFolderPath("Desktop")
$DesktopShortcut = $WshShell.CreateShortcut((Join-Path $DesktopFolder "AnonGuard.lnk"))
$DesktopShortcut.TargetPath = (Join-Path $InstallDir "anonguard-daemon.exe")
$DesktopShortcut.Arguments = "--listen 127.0.0.1:$Port --onion"
if ($QuantumFlag -eq "true") { $DesktopShortcut.Arguments += " --quantum" }
$DesktopShortcut.WorkingDirectory = $InstallDir
$DesktopShortcut.Save()
Write-Host "[✓] Created Desktop shortcut: AnonGuard.lnk" -ForegroundColor Green

Write-Host ""
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "🎉 AnonGuard Setup Complete!" -ForegroundColor Green
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "SOCKS5 Proxy Endpoint:  127.0.0.1:$Port" -ForegroundColor White
Write-Host ""
Write-Host "How to use in your browser (Chrome / Edge / Firefox / Brave):" -ForegroundColor Yellow
Write-Host "  1. Open Windows Settings -> Network & internet -> Proxy"
Write-Host "  2. Turn on 'Use a proxy server'"
Write-Host "  3. Set Proxy IP: 127.0.0.1 | Port: $Port"
Write-Host "  (Or configure Firefox SOCKS5 directly to 127.0.0.1:$Port with remote DNS)"
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host ""
