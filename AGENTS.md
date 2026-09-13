# AGENTS.md — Secure File Transfer (C++20)

> Reference: `MASTER.md` is the single source of truth (topology, crypto, threat model, roadmap). This file is only the agent shortcut. If they conflict, trust `MASTER.md` + executable config.

## Stack & Topology
- C++20, CMake 3.20+, Ninja. Deps via `FetchContent`: `googletest v1.14.0`, `asio asio-1-30-2` (header-only, at `build/_deps/asio-src/asio/include`). No other UI/crypto deps in Stage-0.
- Two exes: `sft_server` (owns SQLite/encrypted store) + `sft_client` (many instances). Port `5000` fixed — never change (firewall story). Raw TCP + TLS 1.3 framing `[uint32 BE len][msg]` behind `ITransport` (`include/ports/transport.hpp`). App/domain must never include Asio/OpenSSL.
- Trust model: server trusted for identity/metadata/storage but **never** holds Bob's private key or plaintext PDF. Alice encrypts (per-file AES-256-GCM DEK wrapped to Bob's pubkey); server adds at-rest layer; Bob decrypts locally.

## Build / Run / Test (exact)
```bash
cmake -S . -B build -G Ninja
cmake --build build
./build/sft_server.exe --port 5000          # prints IPv4 + FINGERPRINT
./build/sft_client.exe --server 127.0.0.1 --port 5000
ctest --test-dir build --output-on-failure  # all tests
./build/sft_tests.exe --gtest_filter=Stage0Gate.*   # single suite
./build/sft_tests.exe --gtest_filter=Policy.OwnerRecipientStranger
./build/sft_tests.exe --gtest_list_tests
```
- Fresh build glob: `file(GLOB APP_SRCS src/*/*.cpp src/*/*/*.cpp)` + `file(GLOB TEST_SRCS tests/*/*.cpp)` — adding a file needs no CMake edit, just rebuild.
- `config.example.ini` is placeholder only (no secrets). Server `storage` path = `./storage/encrypted/` on server laptop only; ignored via `.gitignore`.

## Project Boundaries
```
include/domain/       pure C++, no library includes (User, FileRecord, Transfer, Permission, DownloadToken, AuditEvent, ids, Digest, WrappedKey)
include/application/  TransferService, AuthenticationService, PolicyEngine
include/ports/        IStorage, IEncryptionProvider, IPasswordHasher, IAuditLogger, IAccessPolicy, ITransport, repositories
include/infrastructure/ AsioTlsTransport, FakeTransport, BinaryFileStorage/MemoryStorage, SqliteRepo/MemoryRepo, FakeCrypto, VectorAudit
include/presentation/  CLI + ANSI (Stage-0); FTXUI later lives ONLY in presentation/ — domain/app never include it
src/                  mirrors include; client/ + server/ are thin main.cpp wrappers parsing --server/--port
tests/{domain,application,infra,integration,presentation,smoke}
certs/  storage/encrypted/  docs/STAGE0-DEMO.md  build/
```
- OOP proof: every port has Real + Fake; substitute via ctor injection (`TransferService(storage+crypto+audit)`). Never `new` owning raw ptr — `unique_ptr`.

## Invariants Agents Must Not Break
- Passwords: Argon2id (never SHA). Auth failures = generic message, per-account rate-limit/lockout.
- File crypto: random DEK + fresh 96-bit nonce per file, 128-bit GCM tag. `is_available()` check. SHA-256(plaintext) is diagnostic only, never dedup key.
- Tokens: opaque `dl_<32B CSPRNG>` store `SHA256(token)` only. Valid iff `hash==stored ∧ ¬revoked ∧ now<expires ∧ uses<max ∧ bind==authUser`. Never log raw token.
- AuthZ: default-deny `owner ∨ active ∧ ¬revoked ∧ now<expires` in one `isAuthorized()`. Check **before** touching disk.
- Transport: `verify_none` forbidden in prod path. Stage-0 = pinned fingerprint `FAKE-SHA256-STAGE0-DEMO`; Final = Demo CA chain.
- Storage: `tmp.<uuid>.part → fsync → rename (same FS) → fsync-dir → BEGIN IMMEDIATE → COMMIT`; fail → `remove()`; boot sweeper deletes orphans. `UNIQUE(upload_id)` (UUIDv4).
- Audit: append-only hash chain `msgHash=SHA256(canonicalJSON)`, `prevHash` link, UTC RFC3339. Never log passwords/keys/plaintext/paths. `audit-verify` must detect mutate/delete/reorder.
- Errors: typed `AppException` tree (Validation/Auth/NotFound/Storage/Crypto/Integrity/Transport) → generic client string, detail only in protected server log.

## Conventions & Gotchas
- CLI prompts: Yes/No only (`Upload <name> for Bob? [y/N]`). See `include/presentation/cli.hpp: askYesNo`. Use `ansi.hpp` colors, no third-party UI in Stage-0.
- Original filename is display metadata; disk name = server-generated `uuid.bin` under `storage/encrypted/`. Never expose plaintext path.
- `docs/STAGE0-DEMO.md` is the viva script (hotspot → server prints `SERVER IPv4 PORT FINGERPRINT` → Alice upload → Bob download → Carol DENY → flip 1 byte → INTEGRITY_FAIL).
- Roadmap is goal-gated: Stage 0 complete → Stage 1 auth → Stage 2 send/store → Stage 3 receive/decrypt → stretch (multi-file, resume, more formats). No compensating later for earlier GREEN failure.

## Sources to Check First
- `MASTER.md` §3c/§3d/§4 for framing/PKI/crypto params
- `system_architecture.md` for layer diagram, `project_description.md` for scope
- `include/domain/*.hpp` and `include/ports/*.hpp` for contracts
- `tests/integration/test_stage0_gate.cpp` for Stage-0 GREEN gate
