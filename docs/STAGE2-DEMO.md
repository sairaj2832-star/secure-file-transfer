# Stage 2 Demo — Single-PDF Blind Server E2E (real TLS :5000)

> Goal: Prove Alice encrypts on her laptop (DEK+nonce → AES-256-GCM → sealed to Bob pubkey), server stores opaque ciphertext blind (never decrypts), Bob decrypts locally, Carol DENY, tamper INTEGRITY_FAIL, kill-9 no orphans. All over real TLS 1.3 `AsioTlsTransport/Listener` `verify_peer` DER fingerprint pin.

## Prerequisites
- Build: `cmake -S . -B build -G Ninja && cmake --build build`
- Certs: `certs/test_server.crt` + `certs/test_server.key` exist (or generate: `openssl req -x509 -newkey rsa:2048 -keyout certs/test_server.key -out certs/test_server.crt -days 30 -nodes -subj "/CN=127.0.0.1"`). Fingerprint shown by server is `SHA256(DER)` via `i2d_X509 + EVP_sha256`, pinned in client `TrustConfig`.
- No `verify_none` in production path: `rg "verify_none" src/infrastructure/asio_tls*` must be empty.

## Manual Hotspot Demo (3 laptops + optional 4th Carol)

### 1. Server laptop — hotspot + start
- Enable mobile hotspot (e.g. `192.168.137.1`). Allow firewall for `5000`.
- Run: `.\build\sft_server.exe --port 5000`
- Note printed line: `SERVER IPv4 192.168.137.1 PORT 5000 FINGERPRINT=<64-hex DER SHA256>`
- Server owns `storage/encrypted/` (opaque `.bin`) + SQLite `storage/*.db` (WAL) + `recipient_pubkeys` + `Audit` hash chain. Leave running.

### 2. Alice laptop — register + encrypt-before-upload
- Join hotspot. Run: `.\build\sft_client.exe --server 192.168.137.1 --port 5000` (client loads `certs/test_server.crt` as CA + verifies `FINGERPRINT` via `verify_peer`; handshake real TLS, not `FakeTransport`).
- Commands: `r` → register `alice / alice@ex.com / Alice123!` (client `KeyPair::generate()` X25519, pubkey sent to server `recipient_pubkeys`, privkey stays `0600` on client). `l` → login.
- Prompt: `Upload doc.pdf for Bob? [y/N] y` → Yes/No confirmation only.
- Client does: `RAND_bytes DEK 32 + nonce 12 → AES-256-GCM encrypt doc.pdf → crypto_box_seal(DEK, Bob pubkey) → {cipher||tag, wrappedDEK, nonce, digest SHA256(plain)}` . Then `UPLOAD_INIT (recipient=bob, origName=doc.pdf, uploadId=UUIDv4, size, digest, wrapped)` + `UPLOAD_DATA` chunks + `UPLOAD_COMMIT` over framed TLS. Server `checkAuth before disk`, `FileValidator` PDF `%PDF` magic + traversal/oversize, `stagedWrite tmp.<uuid>.part → fsync → rename → fsync-dir → BEGIN IMMEDIATE → INSERT → COMMIT`, `UNIQUE(upload_id)` + sweeper deletes orphans. Server CLI prints `UPLOAD alice->bob`.

### 3. Bob laptop — list + download + decrypt locally
- Join hotspot. Run same client command. `r` → `bob / bob@ex.com / Bob123!!` → `l` → login → `list` → shows `doc.pdf`.
- Prompt: `Download doc.pdf? [y/N] y` → client `DOWNLOAD_REQ(fileId, sess_)` over same TLS. Server `isAuthorized(owner∨recipient)` before `read()` + audit `DOWNLOAD bob`, relays opaque ciphertext+wrappedDEK over TLS (no decrypt). Client `unseal DEK with privkey → verify GCM tag + digest → write doc.pdf`.
- Verify:
  ```powershell
  sha256sum doc.pdf        # on Alice vs Bob — must match
  hexdump -C storage/encrypted/*.bin  # on server — differs from doc.pdf
  rg -a "secret|plaintext" storage/files.db storage/audit.log  # must miss
  rg -a "BEGIN CERTIFICATE" storage/  # cert not mixed with data
  ```

### 4. Carol denied (4th laptop or 3rd after logout)
- Register `carol / carol@ex.com / Carol123!` → login → `download <bob fileId>` → server `DENIED carol` + audit `DENIED` + CLI `DENIED carol`, no bytes sent. `curl` without `sess_` also denied (generic `Login failed`).

### 5. Tamper 1-byte integrity fail
- On server: `Copy-Item storage/encrypted/<uuid>.bin storage/encrypted/<uuid>.bin.bak; $b=[IO.File]::ReadAllBytes("storage/encrypted/<uuid>.bin"); $b[0] = $b[0] -bxor 1; [IO.File]::WriteAllBytes("storage/encrypted/<uuid>.bin",$b)`
- Bob `download` again → client throws `IntegrityException` (`GCM tag mismatch`), no file delivered, server audit `INTEGRITY_FAIL` + CLI `INTEGRITY_FAIL bob`. Restore backup after test.

### 6. Kill-9 no orphans + idempotent retry
- Start large `20MB.pdf` upload from Alice, kill client at ~50% (or `taskkill /PID <client> /F`). Server still has `storage/encrypted/tmp.<uuid>.part`. Restart server → sweeper `sweepOrphans()` deletes `.part` → `ls storage/encrypted/*.part` empty.
- Retry with same `uploadId` (`UUIDv4` from first attempt) → second `UPLOAD_COMMIT` fails generic `duplicate upload_id`, no extra blob, first blob still retrievable via Bob `download`. `BEGIN IMMEDIATE` guarantees no orphan row.

### 7. PDF-only rejection (non-PDF)
- On Alice: try `Upload image.png` with PNG magic `89 50 4E 47...` → `FileValidator` rejects `ValidationException` (`PDF magic`, `PDF-only core`), no file saved, no `*.part` left. `rg "image.png" storage/` must miss.

## Loopback fallback (single machine, 2–3 terminals)
- If hotspot blocked: Terminal1 `.\build\sft_server.exe --port 5000` → `127.0.0.1`. Terminal2 Alice client `--server 127.0.0.1 --port 5000`, Terminal3 Bob client `--server 127.0.0.1 --port 5000`. Same steps; `sha256sum` match + `hexdump` differ still hold. This is how `Stage2Gate.*` tests run: `AsioTlsListener.listen(0)` ephemeral + `AsioTlsTransport.connect(127.0.0.1, port)` with DER fingerprint `verify_peer`.

## Automated gate
```
cmake -S . -B build -G Ninja && cmake --build build && ctest --test-dir build --output-on-failure
.\build\sft_tests.exe --gtest_filter=Stage2Gate.*
```
Expect `Stage2Gate.* 5/5 PASS` + full suite `99/99 PASS`, `verify_none` empty, `rg` no plaintext in `storage/encrypted`.

## Troubleshooting
- `TLS handshake failed` → check `certs/test_server.crt` matches server `FINGERPRINT` (uppercase hex, no colons), `TrustConfig.caPath` points to cert, `verify_peer` not `verify_none`, TLS 1.3 only.
- `address already in use` → kill old `sft_server` or use ephemeral `listen(0)` for tests.
- `cannot remove … being used` on Windows → ensure `SqliteFileRepository`/`SqlitePubkeyDirectory` closed (scope) before `Remove-Item -Force` + remove `-wal/-shm` + `blobRoot` `Remove-Item -Recurse`.

## Cleanup
- `Remove-Item storage/encrypted/*.bin -Force; Remove-Item storage/*.db, storage/*.db-wal, storage/*.db-shm -Force; Remove-Item storage/audit.log -Force` (keep `certs/`).
