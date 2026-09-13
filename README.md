# Secure File Transfer — C++20 (Stage 1)

> **Stack:** C++20 · Asio `ssl::stream` TLS 1.3 (`verify_peer`, DER `SHA-256` pin) · SQLite WAL · Argon2id `m=19456` · AES-256-GCM (Stage 2) · `sft_server` + `sft_client` on fixed `:5000` behind `ITransport`
> **Course:** CI2013 OOP — `MASTER.md` is the spec. `docs/STAGE1-DEMO.md` is the viva script.

## Quick Start

### Prerequisites (once per machine)
- **Windows + MinGW 15.2** (`C:/mingw64/bin/c++.exe` + `ninja`)
- **CMake 3.20+**, **Git**, **PowerShell**
- **OpenSSL for MinGW** — auto-installed by `setup-*.ps1` via `C:/vcpkg` `x64-mingw-dynamic` (~11 min, once). No manual `OPENSSL_ROOT_DIR` needed; `vcpkg` provides `libcrypto.dll.a` next to exe (fixes `OPENSSL_Uplink`).

### One laptop — loopback `127.0.0.1:5000` (proves code, 59/59)
```powershell
# Clone
git clone <your-github-url> sft && cd sft

# One-click server setup (generates certs/server.crt/.key, fingerprint, builds sft_server, creates storage/)
powershell -ExecutionPolicy Bypass -File setup-server.ps1
./build-server/sft_server.exe --port 5000
# prints: SERVER IPv4=127.0.0.1 PORT=5000 FINGERPRINT=60:1D:4E:CE... (real DER SHA-256)

# New terminal — Alice
powershell -ExecutionPolicy Bypass -File setup-client.ps1 -Server 127.0.0.1
./build-client/sft_client.exe --server 127.0.0.1 --port 5000
# 1) Register → alice / alice@example.com / Alice@1234 → y → Registration succeeded
# 2) Login → alice / Alice@1234 → Login succeeded (sess_ token in memory only)
# 3) Logout → Logged out

# New terminal — Bob (same)
./build-client/sft_client.exe --server 127.0.0.1 --port 5000
# Register bob → Login → server prints LOGIN_OK, Wireshark shows Application Data

# Automated (same as above but ephemeral, no hotspot):
cmake -S . -B build -G Ninja -DOPENSSL_ROOT_DIR=C:/vcpkg/installed/x64-mingw-dynamic
cmake --build build
$env:PATH="C:/vcpkg/installed/x64-mingw-dynamic/bin;"+$env:PATH; ctest --test-dir build --output-on-failure
# Must be: -- Found OpenSSL ... 3.6.4  and 100% tests passed, 0 failed out of 59
```

### Two laptops — dedicated server (required for Stage 1 GREEN per `MASTER.md` §3a)

**Server laptop (hotspot + DB + keys):**
```powershell
# 1. Hotspot ON (Settings → Mobile hotspot) → note IPv4 (e.g., 192.168.137.1)
# 2. Run setup (same as above, but will use hotspot IP for cert SAN)
setup-server.ps1 -Port 5000
# 3. Allow Firewall for 5000 when prompted (keep 5000 forever)
./build-server/sft_server.exe --port 5000
# Must print real DER FINGERPRINT, not FAKE, and TLS 1.3 verify_peer
# First run: No users — initial admin setup → admin / admin@example.com / Admin@1234 → Registration succeeded
```

**Each client laptop (Alice/Bob/Carol):**
```powershell
# 1. Join server's hotspot Wi-Fi (no college WiFi/AP-isolation)
# 2. Copy certs/server.crt from server via USB to ./certs/server.crt (or verify fingerprint out-of-band)
setup-client.ps1 -Server 192.168.137.1 -Port 5000
./build-client/sft_client.exe --server 192.168.137.1 --port 5000
# Verify FINGERPRINT matches server screen before y/N
# Same Register/Login/Logout/Admin flow — Wireshark tcp.port==5000 shows Application Data, not plaintext
```

**Reset demo:** `Remove-Item storage/users.db,storage/audit.log -Force` → restart server (re-prompts admin).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `OPENSSL_Uplink: no OPENSSL_Applink` | MinGW exe loaded ShiningLight MSVC DLL (`C:/Program Files/OpenSSL-Win64/bin`) | `CMakeLists.txt` now auto-copies `C:/vcpkg/installed/x64-mingw-dynamic/bin/libcrypto-3-x64.dll` next to exe on `cmake --build` — just rebuild, no `PATH` hack needed |
| `Registration failed` for `sai/sai123` | `pw.size()<8` (`MASTER.md` §4) | Use `≥8` chars, e.g., `Sai@1234` |
| `cmake` `OPENSSL_CRYPTO_LIBRARY missing` | `ShiningLight` 4.0.2 found but MSVC lib, not MinGW | Use `C:/vcpkg/installed/x64-mingw-dynamic` (`libssl.dll.a`/`libcrypto.dll.a` 3.6.4) — `setup-*.ps1` handles it |
| `ctest` `RealTLSLiveEphemeral` `handshake: certificate verify failed` | Wrong `fingerprint` or `SAN` mismatch | Regenerate `certs/server.crt` with `SAN=IP:<server-IP>` and `config.example.ini` `fingerprint` = `openssl x509 -fingerprint -sha256 -in certs/server.crt` (no colons, uppercase) |
| `cannot remove: being used` on `ctest` | `sqlite3` handle still open (Windows) | Tests now scope `SqliteUserRepository` before `fs::remove` + `remove -wal/-shm` |

## Project Layout

```
include/domain/      User, Session, Result, IClock (no Asio/OpenSSL)
include/ports/       ITransport, ITransportListener, IUserRepository, IPasswordHasher, ISessionStore
include/infrastructure/  AsioTlsTransport/Listener (ssl::stream), SqliteUserRepository, Argon2Hasher, HashChainFileAuditLogger, sha256 (real)
src/                 mirrors include
tests/               59 tests (domain, infra, integration)
certs/               server.crt/.key (gitignored, generated), test_server.crt/.key (committed, for ctest)
docs/STAGE1-DEMO.md  viva script, docs/impl-logs/stage-0-impl-log.md  full log
CMakePresets.json    presets: server (build-server), client (build-client), ci-loopback (build)
setup-server.ps1 / setup-client.ps1  one-click (vcpkg + certs + build)
```

## Next Stage

Stage 1 basic auth lifecycle is GREEN on loopback with real TLS (`59/59`). Stage 2 per `MASTER.md` §10 is single-PDF `RAND_bytes` DEK + `AES-256-GCM` + `WrappedKey` to Bob pubkey + server at-rest.

License: Course project — not production.
