# Secure File Transfer — C++20 (Stage 2 GREEN)

> **Stack:** C++20 · Asio `ssl::stream` TLS 1.3 (`verify_peer`, DER `SHA-256` pin) · SQLite WAL · Argon2id `m=19456` · AES-256-GCM per-file DEK + X25519 sealed-box (E2E blind server) · `sft_server` + `sft_client` on fixed `:5000` behind `ITransport` · **99/99 ctest GREEN**
> **Course:** CI2013 OOP — `docs/MASTER.md` is the spec. Viva scripts: `docs/STAGE1-DEMO.md` (auth) · `docs/STAGE2-DEMO.md` (single-PDF E2E blind).

## What Works (Stage 2)

- **Auth:** Register / login / logout, `sess_` CSPRNG (`SHA-256` stored), per-account lockout (5 fails / 15 min), admin activate/deactivate + last-admin guard — `Stage1Gate.*` 5/5 over real ephemeral TLS.
- **E2E Blind Transfer (PDF-only core):** Alice generates X25519 keypair on register (pubkey → server `recipient_pubkeys`, privkey never leaves client), encrypts PDF locally with random 32B DEK + 12B nonce → AES-256-GCM (128-bit tag), seals DEK to Bob's pubkey (`ephPub || encDEK` via ECDH+SHA256 KDF, libsodium seal semantics), uploads opaque ciphertext+wrappedDEK over TLS framing; server validates (`%PDF` magic + traversal/oversize), `stagedWrite tmp.<uuid>.part → fsync → rename → fsync-dir → BEGIN IMMEDIATE → COMMIT`, `UNIQUE(upload_id)` + sweeper — server **never decrypts**; Bob downloads via `isAuthorized(owner ∨ recipient)` + relays opaque blob → unwraps with privkey → verifies GCM tag + `SHA-256(plaintext)` digest. `Stage2Gate.*` 5/5 over real TLS.
- **Guarantees:** 10k nonce uniqueness, tag/wrong-key → `IntegrityException`, 1-byte tamper `INTEGRITY_FAIL` (no delivery), Carol/stranger `DENY` audited, kill at 50% leaves no `*.part` (sweeper), `rg verify_none src/infrastructure/asio_tls*` empty, `rg` no plaintext/privkey in DB/audit, `hexdump` server blob ≠ PDF.

## Quick Start

### Prerequisites (once per machine)
- **Windows + MinGW 15.2** (`C:/mingw64/bin/c++.exe` + `ninja`) · **CMake 3.20+** · **Git** · **PowerShell**
- **OpenSSL for MinGW** — auto-installed by `setup-*.ps1` via `C:/vcpkg` `x64-mingw-dynamic` (~11 min, once). No manual `OPENSSL_ROOT_DIR` needed; build auto-copies `libcrypto-3-x64.dll`/`libssl-3-x64.dll` next to exe (fixes `OPENSSL_Uplink`).

### One laptop — loopback `127.0.0.1:5000` (99/99)
```powershell
git clone https://github.com/sairaj2832-star/secure-file-transfer.git sft && cd sft

# One-click server setup (generates certs/server.crt/.key, DER fingerprint, builds sft_server, creates storage/)
powershell -ExecutionPolicy Bypass -File setup-server.ps1
./build-server/sft_server.exe --port 5000
# prints: SERVER IPv4=127.0.0.1 PORT=5000 FINGERPRINT=AA:BB:CC... (real DER SHA-256 via i2d_X509 + EVP_sha256)

# New terminal — Alice (encrypts for Bob)
powershell -ExecutionPolicy Bypass -File setup-client.ps1 -Server 127.0.0.1
./build-client/sft_client.exe --server 127.0.0.1 --port 5000
# Register alice / alice@example.com / Alice@1234 → y → Registration succeeded (X25519 keypair, pubkey to server)
# Login alice / Alice@1234 → y → Upload doc.pdf for Bob? [y/N] y

# New terminal — Bob (decrypts locally)
./build-client/sft_client.exe --server 127.0.0.1 --port 5000
# Register bob / bob@example.com / Bob@1234 → Login → prompt Download doc.pdf? [y/N] y
# sha256sum doc.pdf on Alice vs Bob must match; hexdump storage/encrypted/*.bin differs

# Automated same-lab gate (ephemeral real TLS, no hotspot)
cmake -S . -B build -G Ninja -DOPENSSL_ROOT_DIR=C:/vcpkg/installed/x64-mingw-dynamic
cmake --build build
$env:PATH="C:/vcpkg/installed/x64-mingw-dynamic/bin;"+$env:PATH; ctest --test-dir build --output-on-failure
# Must be: -- Found OpenSSL ... 3.6.4  and  100% tests passed, 0 failed out of 99
./build/sft_tests.exe --gtest_filter=Stage2Gate.*
# Must be: Stage2Gate.* 5/5 PASS (SinglePdfAliceToBob · CarolDenied · TamperOneByte · Kill9NoOrphans · PdfOnlyRejects)
```

### Two laptops — dedicated blind server (hotspot, required for viva per `docs/MASTER.md §3a`)
**Server laptop (hotspot + DB + opaque store + pubkey directory):**
```powershell
# 1. Mobile hotspot ON → note IPv4 e.g. 192.168.137.1
setup-server.ps1 -Port 5000   # rerun if hotspot IP changed (regens SAN IP in cert)
# 2. Allow Firewall for 5000 when prompted (keep 5000 forever)
./build-server/sft_server.exe --port 5000
# Must print real DER FINGERPRINT, not FAKE, TLS 1.3 verify_peer
# First run: No users — initial admin setup → admin / admin@example.com / Admin@1234
```
**Each client laptop (Alice / Bob / Carol):**
```powershell
# 1. Join server hotspot (no college WiFi / AP isolation)
# 2. Copy certs/server.crt from server via USB to ./certs/server.crt (or verify fingerprint out-of-band)
setup-client.ps1 -Server 192.168.137.1 -Port 5000
./build-client/sft_client.exe --server 192.168.137.1 --port 5000
# Verify FINGERPRINT matches server screen before y/N → same Register/Login/Upload-for-Bob / Download flow
# Wireshark tcp.port==5000 shows Application Data, not plaintext; Carol download → DENY + audit DENIED
```
**Reset demo:** `Remove-Item storage/encrypted/*.bin,storage/*.db,storage/*.db-wal,storage/*.db-shm,storage/audit.log -Force` → restart server (re-prompts admin, sweeper clears `*.part`).

## Verification Checklist (must all pass before claiming GREEN)

```powershell
ctest --test-dir build --output-on-failure                      # 99/99
rg "verify_none" src/infrastructure/asio_tls*                   # must be empty
rg -a "BEGIN CERTIFICATE|privkey|DEK.*plain" storage/            # no secrets in blobs
sha256sum doc.pdf ; sha256sum bob_downloaded_doc.pdf             # must match
$h = Get-FileHash doc.pdf -Algorithm SHA256; $b = Get-FileHash storage/encrypted/*.bin -Algorithm SHA256; $h.Hash -ne $b.Hash  # true
# Tamper: flip 1 byte in storage/encrypted/*.bin → Bob download throws IntegrityException + audit INTEGRITY_FAIL, no file delievered
```

## Project Layout
```
include/domain/       User, Session, Result, IClock, KeyPair, WrappedKey, FileRecord (blind), ids, Digest, exceptions
include/ports/        ITransport/Listener, IUserRepository, IPasswordHasher, ISessionStore, IKeyDirectory, IFileRepository, IFileValidator
include/infrastructure/ AsioTlsTransport/Listener (ssl::stream), SqliteUserRepository/PubkeyDirectory/FileRepository, Argon2Hasher,
                      HashChainFileAuditLogger, ClientCryptoProvider (AES-GCM + X25519 seal), BinaryFileStorage (fsync+rename+sweeper), PdfFileValidator
src/                  mirrors include; client/ + server/ thin mains parsing --server/--port
tests/                99 tests: domain, infra (crypto/storage/validator/pubkey), application (transfer E2E), integration Stage1/2 gates, framing, tls, cli
certs/                server.crt/.key (gitignored, generated), test_server.crt/.key (committed for ctest)
docs/                 MASTER.md (spec), system_architecture.md, project_description.md, STAGE1-DEMO.md, STAGE2-DEMO.md, impl-logs/, superpowers/plans/
CMakePresets.json     presets: server (build-server), client (build-client), ci-loopback (build)
setup-server.ps1 / setup-client.ps1  one-click vcpkg + certs + build
```

## Troubleshooting
| Symptom | Cause | Fix |
|---|---|---|
| `OPENSSL_Uplink: no OPENSSL_Applink` | MinGW exe loaded ShiningLight MSVC DLL | Rebuild — `CMakeLists.txt` auto-copies `C:/vcpkg/.../bin/libcrypto-3-x64.dll` next to exe |
| `Registration failed` for short pw | `pw.size()<8` (`docs/MASTER.md §4`) | Use ≥8 chars, e.g. `Alice@1234` |
| `OPENSSL_CRYPTO_LIBRARY missing` | ShiningLight 4.0.2 found (MSVC) | Use `C:/vcpkg/installed/x64-mingw-dynamic/lib/libcrypto.dll.a` (3.6.4) — `setup-*.ps1` handles it |
| `certificate verify failed` | Wrong fingerprint / SAN mismatch | Regenerate `certs/server.crt` with `SAN=IP:<server-IP>` and fingerprint = `openssl x509 -fingerprint -sha256 -in certs/server.crt` (no colons, uppercase) → `computeSha256Fingerprint` is DER via `i2d_X509+EVP_sha256` |
| `cannot remove: being used` on ctest | sqlite handle open (Windows) | Tests scope repo before `fs::remove` + `remove -wal/-shm` + `remove_all blobRoot` |
| Download returns `DENY` for Bob | Not owner/recipient or `sess_` expired | Re-login; check `isAuthorized(owner∨recipient) before disk` + `MemorySessionStore::isValid` |
| `PdfOnlyRejects` / upload blocked | Non-PDF magic | Core is PDF-only (`%PDF` at 0 + `.pdf` suffix + `lexically_normal` + no `../`/`\0`/double-ext `.pdf.`), retry with real `%PDF` file |

## Roadmap
- **Stage 0** folded → **Stage 1** Auth (real TLS, `59→99` with Stage 2) → **GREEN**
- **Stage 2** Send & Secure Store (Alice encrypts → blind server stores opaque → Bob decrypts, PDF-only) → **GREEN (current)**
- **Stage 3** Receive & Decrypt hardened (PolicyEngine default-deny before disk, opaque `dl_*` tokens `SHA256` stored, AuditVerifier chain, stretched E2E relay via `UPLOAD_INIT/DATA/COMMIT` + `DOWNLOAD_REQ`)
- **Stretch** (after core GREEN, in order): multi-file batch → multi-format (PNG/JPG/ZIP/DOCX magic) → resumable `UploadSession` offset → expiring `Grant` + `DownloadToken` 60s → hash-chain `audit-verify`

All live gates use **real** `AsioTlsTransport/AsioTlsListener` TLS 1.3 (`verify_peer`); `FakeTransport/FakeCrypto` only in unit tests to prove polymorphism.

## Docs
- Spec: `docs/MASTER.md` · Architecture: `docs/system_architecture.md` · Stage 2 viva: `docs/STAGE2-DEMO.md` · Stage 1 viva: `docs/STAGE1-DEMO.md` · Log: `docs/impl-logs/stage-0-impl-log.md`

License: Course project — not production.
