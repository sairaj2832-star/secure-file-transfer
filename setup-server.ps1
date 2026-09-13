# setup-server.ps1 — One-click server setup (dedicated laptop, port 5000, real TLS)
# Run on SERVER laptop:  powershell -ExecutionPolicy Bypass -File setup-server.ps1
param([string]$Port = "5000")
$ErrorActionPreference = "Stop"
Write-Host "=== SFT Server Setup (port $Port) ===" -ForegroundColor Green

# 1. vcpkg OpenSSL for MinGW (if missing)
if (!(Test-Path "C:/vcpkg/installed/x64-mingw-dynamic/include/openssl/ssl.h")) {
  Write-Host "Installing OpenSSL x64-mingw-dynamic via vcpkg (~11 min, once)..." -ForegroundColor Yellow
  if (!(Test-Path "C:/vcpkg/vcpkg.exe")) { git clone https://github.com/microsoft/vcpkg C:/vcpkg --depth 1; C:/vcpkg/bootstrap-vcpkg.bat }
  C:/vcpkg/vcpkg install openssl:x64-mingw-dynamic --host-triplet=x64-mingw-dynamic --clean-after-build
}

# 2. Certs (real self-signed, SAN=server IP, not dummy)
if (!(Test-Path "certs/server.crt") -or !(Test-Path "certs/server.key")) {
  Write-Host "Generating certs/server.crt/.key (SAN=127.0.0.1 + hotspot IP)..." -ForegroundColor Yellow
  New-Item -ItemType Directory -Force -Path certs | Out-Null
  $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -like "192.168.*" } | Select-Object -First 1).IPAddress
  if (!$ip) { $ip = "127.0.0.1" }
  & "C:/Program Files/OpenSSL-Win64/bin/openssl.exe" req -x509 -newkey rsa:2048 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/CN=$ip" -addext "subjectAltName=IP:$ip,IP:127.0.0.1" 2>$null
  Copy-Item certs/server.crt certs/test_server.crt -Force
  Copy-Item certs/server.key certs/test_server.key -Force
  & "C:/Program Files/OpenSSL-Win64/bin/openssl.exe" x509 -fingerprint -sha256 -in certs/server.crt -noout
}

# 3. Config fingerprint
$fp = & "C:/Program Files/OpenSSL-Win64/bin/openssl.exe" x509 -fingerprint -sha256 -in certs/server.crt -noout 2>$null
$fp = $fp -replace ".*=","" -replace ":","" 
Write-Host "FINGERPRINT=$fp" -ForegroundColor Cyan
if (Test-Path config.example.ini) {
  (Get-Content config.example.ini) -replace 'fingerprint=.*',"fingerprint=$fp" | Set-Content config.example.ini
}

# 4. Build server only
Write-Host "Configuring + building sft_server (preset server)..." -ForegroundColor Yellow
cmake --preset server
cmake --build --preset server

# 5. Storage
New-Item -ItemType Directory -Force -Path storage | Out-Null
Write-Host "=== Server ready ===" -ForegroundColor Green
Write-Host "Run: ./build-server/sft_server.exe --port $Port" -ForegroundColor White
Write-Host "It will print: SERVER IPv4=<hotspot IP> PORT=$Port FINGERPRINT=$fp" -ForegroundColor Gray
Write-Host "Allow Windows Firewall for $Port when prompted." -ForegroundColor Yellow
