# Stage-0 Demo (3 laptops, hotspot, :5000)

## Setup
1. Server laptop: mobile hotspot ON → `sft_server --port 5000` → note IPv4 + FINGERPRINT.
2. Windows Firewall: Allow on first prompt.
3. Alice laptop: `sft_client --server <IPv4> --port 5000` → register/login → `Upload report.pdf for Bob? [y/N] y`.
4. Bob laptop: same client → login → `Download report.pdf? [y/N] y` → sha256 matches.
5. Carol laptop (or same): login carol → download → `denied` + server audit DENIED.
6. Tamper: server `python -c "flip 1 byte in storage/encrypted/uuid-*.bin"` → Bob download → INTEGRITY_FAIL, no file.
7. Fallback: wired switch / USB-tether if hotspot blocked. `reset-demo` = delete storage/* + restart.

## Loopback verification (single machine)
```bash
# Terminal 1
./build/sft_server.exe --port 5000
# Terminal 2 (Alice)
./build/sft_client.exe --server 127.0.0.1 --port 5000
# Terminal 3 (Bob)
./build/sft_client.exe --server 127.0.0.1 --port 5000
```

## Expected outputs
- Server prints: `SERVER IPv4=127.0.0.1 PORT=5000 FINGERPRINT=FAKE-SHA256-STAGE0-DEMO`
- Alice upload: `Uploaded, transferId: t1`
- Bob download: `Downloaded 30 bytes`
- Carol download: `denied`
- Tamper: `IntegrityException: tag mismatch` + audit shows `INTEGRITY_FAIL`