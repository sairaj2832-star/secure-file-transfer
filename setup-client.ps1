# setup-client.ps1 — One-click client setup (Alice/Bob/Carol laptops)
# Run on EACH CLIENT laptop:  powershell -ExecutionPolicy Bypass -File setup-client.ps1 -Server 192.168.137.1
param([string]$Server = "192.168.137.1", [string]$Port = "5000")
$ErrorActionPreference = "Stop"
Write-Host "=== SFT Client Setup (server $Server`:$Port) ===" -ForegroundColor Green

# 1. vcpkg OpenSSL (same as server, ~11 min once)
if (!(Test-Path "C:/vcpkg/installed/x64-mingw-dynamic/include/openssl/ssl.h")) {
  Write-Host "Installing OpenSSL x64-mingw-dynamic via vcpkg..." -ForegroundColor Yellow
  if (!(Test-Path "C:/vcpkg/vcpkg.exe")) { git clone https://github.com/microsoft/vcpkg C:/vcpkg --depth 1; C:/vcpkg/bootstrap-vcpkg.bat }
  C:/vcpkg/vcpkg install openssl:x64-mingw-dynamic --host-triplet=x64-mingw-dynamic --clean-after-build
}

# 2. Get server cert fingerprint (out-of-band: read from server screen or copy via USB)
# For hotspot demo, copy certs/server.crt from server laptop via USB/share to ./certs/server.crt
if (!(Test-Path "certs/server.crt")) {
  Write-Host "WARNING: certs/server.crt not found — copy it from server laptop via USB" -ForegroundColor Yellow
  Write-Host "Alternatively, fingerprint will be verified interactively on first connect." -ForegroundColor Gray
} else {
  $fp = & "C:/Program Files/OpenSSL-Win64/bin/openssl.exe" x509 -fingerprint -sha256 -in certs/server.crt -noout 2>$null
  Write-Host "Pinned FINGERPRINT=$fp" -ForegroundColor Cyan
}

# 3. Build client only
Write-Host "Configuring + building sft_client (preset client)..." -ForegroundColor Yellow
cmake --preset client
cmake --build --preset client

Write-Host "=== Client ready ===" -ForegroundColor Green
Write-Host "Run: ./build-client/sft_client.exe --server $Server --port $Port" -ForegroundColor White
Write-Host "Verify fingerprint matches server screen before Yes/No upload." -ForegroundColor Yellow
Write-Host "Menu: 1) Register  2) Login  3) Logout  4) Quit" -ForegroundColor Gray
