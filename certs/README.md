# Trust — Stage 0 → Stage 1
Stage-0: Server prints FAKE-SHA256-STAGE0-DEMO. Clients verify the displayed string matches config before Yes/No upload. No USB transfer required. This fake fingerprint is allowed only in FakeTransport/FakeListener tests.

Stage-1: Generate a real self-signed cert:
```
openssl req -x509 -newkey rsa:2048 -keyout certs/server.key -out certs/server.crt -days 30 -nodes -subj "/CN=127.0.0.1"
openssl x509 -fingerprint -sha256 -in certs/server.crt | cut -d= -f2 | tr -d ':' | tr 'a-z' 'A-Z' > certs/server.fingerprint
```
Put the hex (no colons, uppercase) into config.example.ini [trust] fingerprint, cert_path=./certs/server.crt, key_path=./certs/server.key.
AsioTlsTransport/Listener always use verify_peer and check SHA256 fingerprint via computeSha256Fingerprint(); never verify_none. Test certs in certs/test_server.crt/.key are for automated tests only.

Bootstrap admin: first run prompts interactively for username/email/password (no hardcoded admin/admin123); or place storage/bootstrap_admin.json with 0600 perms, deleted after use. Never use env var with plaintext password.