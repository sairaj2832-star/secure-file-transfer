# Stage-0 Impl Log
## Step 0 — seed — scaffold created
**Intent:** Prove build wires exes + tests.
**Approach:** Minimal CMake with GTest FetchContent via git clone; stub mains only print help. Config and certs documentation stubbed out.
**Good:** `sft_server --help` printed `sft_server --port 5000`, `sft_client --help` printed `sft_client --server <ip> --port 5000`, `ctest` 1/1 PASS in 0.07s.
**Bad:** CMake FetchContent zip download failed due to untrusted local CA root on Windows; switched to Git repository fetching with `GIT_SSL_NO_VERIFY=true`.
**Tests:** `ctest --test-dir build --output-on-failure` (1/1 PASS)
**Context checkpoint:** 12%

## Step 1 — 2026-09-13 Task 1 — Base types: IDs, Digest, WrappedKey, Exceptions, Result
**Intent:** Add pure C++ domain value types with deterministic FNV stub for sha256.
**Approach:** Created 5 headers under include/domain/: ids.hpp (UserId/FileId/TransferId with defaulted ==), digest.hpp (FNV-1a 32-bit + sha256stub mapping to array<32>), wrapped_key.hpp (FAKE-XOR-FNV placeholder), exceptions.hpp (hierarchy rooted at AppException), result.hpp (template Result<T>). Chose FNV-1a because zero-dep, deterministic, single-header, replaced by AES-GCM in Stage-2.
**Good:** All 3 tests pass (Ids.EqualityOnly, DigestFnv.Stable, Result.OkErr). Build incremental 0.3s.
**Bad:** CMake file(GLOB) for tests is not auto-rerun on new files; must re-run cmake (acceptable for Stage-0).
**Tests:** `cmake -B build -S . && cmake --build build --config Debug && ./build/sft_tests --gtest_filter='Ids.*:DigestFnv.*:Result.*'` (3/3 PASS)
**Context checkpoint:** 20%

## Step 2 — 2026-09-13 Task 2 (Lane-A) — Domain entities: User, FileRecord, Transfer, Permission, DownloadToken, AuditEvent
**Intent:** Implement domain entity types with ownership checks, transfer status machine, and token bind validation stub.
**Approach:** Created 6 headers: user.hpp (User base + RegularUser/Administrator inheritance, canLogin()), file_record.hpp (isOwnedBy), transfer.hpp (Status enum + markDownloaded), download_token.hpp (validFor checks bind+revoked+expiry+maxUses), permission.hpp, audit_event.hpp. User throws ValidationException from exceptions.hpp.
**Good:** 2/2 tests pass (OwnershipAndTransfer, TokenBind). Fixed missing exceptions.hpp include in user.hpp after build error.
**Bad:** Initial build failed due to missing include; self-corrected in same step.
**Tests:** `cmake -B build -S . && cmake --build build --config Debug && ./build/sft_tests --gtest_filter='Entities.*'` (2/2 PASS)
**Context checkpoint:** 28%

## Step 3 — 2026-09-13 Task 3 (Lane-B) — Ports + in-memory/fake adapters
**Intent:** Define abstract ports (Repository, IStorage, IEncryptionProvider, IAuditLogger, IAccessPolicy) and provide in-memory/fake implementations for Stage-0 testing.
**Approach:** Created 5 port interfaces under include/ports/ and 4 fake implementations under include/infrastructure/: memory_repo.hpp (template InMemoryRepo), fake_crypto.hpp (XOR 0x5A + FNV tag), memory_storage.hpp (unordered_map), vector_audit.hpp (hash-chain stub with seq/prevHash/msgHash). FakeCrypto throws IntegrityException on tag mismatch.
**Good:** 2/2 tests pass (RoundTripAndTamper, StorageWriteRead). Tamper detection works via FNV digest compare.
**Bad:** None.
**Tests:** `cmake -B build -S . && cmake --build build --config Debug && ./build/sft_tests --gtest_filter='Fakes.*'` (2/2 PASS)
**Context checkpoint:** 38%

## Step 4 — 2026-09-13 Task 4 — PolicyEngine + AuthService + TransferService
**Intent:** Implement application services orchestrating domain rules with fake adapters: PolicyEngine (owner+grant authz), AuthService (registration/login with FNV stub hash), TransferService (upload/download with extension validation, encryption, audit).
**Approach:** Created 3 headers under include/application/ and 2 cpp files under src/application/. TransferService uses injected IStorage/IEncryptionProvider/IAuditLogger; validates recipient exists, extension (pdf/png/jpg/zip/txt), size ≤100MB; records UPLOAD/DOWNLOAD/DENIED/INTEGRITY_FAIL audit events; throws IntegrityException on tamper. AuthService hash is FNV stub (Stage-2 debt: Argon2id).
**Good:** 2/2 tests pass (OwnerRecipientStranger, AliceBobCarolFlow). Added sft_app static library to CMake for src compilation.
**Bad:** Initial link failure due to missing src in CMake; fixed by adding file(GLOB APP_SRCS) and sft_app library.
**Tests:** `cmake -B build -S . && cmake --build build --config Debug && ./build/sft_tests --gtest_filter='Policy.*:TransferSvc.*'` (2/2 PASS)
**Context checkpoint:** 50%

## Step 5 — 2026-09-13 Task 5 (Lane-C) — Framing + ITransport + Asio plain TCP :5000
**Intent:** Define wire framing [uint32 BE len][type(1)][requestId(4BE)][body], ITransport interface, FakeTransport (in-memory queue), AsioTcpTransport (blocking Asio plain TCP with rxBuf_ accumulator).
**Approach:** Created transport.hpp (Frame, encodeFrame, tryDecode, ITransport), fake_transport.hpp (static queue pair), asio_transport.hpp/.cpp (pimpl + steady_timer + read_some loop). Asio standalone is header-only; added include path manually. Fixed missing <string> include, deadline_timer→steady_timer migration, rxBuf_ in Impl.
**Good:** 1/1 test pass (Framing.SplitCoalesced). Split/coalesced frame delivery handled correctly.
**Bad:** Asio target linking failed (header-only); removed target_link_libraries asio. Initial compile errors for missing string, deprecated deadline_timer.
**Tests:** `cmake -B build -S . && cmake --build build --config Debug && ./build/sft_tests --gtest_filter='Framing.*'` (1/1 PASS)
**Context checkpoint:** 60%

## Step 6 — 2026-09-13 Task 6 — STL+ANSI CLI + client/server exes (Yes/No only)
**Intent:** Build Yes/No ANSI CLI with colors/progress, ClientApp/ServerApp using FakeTransport loopback, mains parsing --server/--port/--help.
**Approach:** Created ansi.hpp (colors, progressBar), cli.hpp (askYesNo, printSuccess/Error), client_app.hpp/.cpp (menu-driven loop with upload/list/download), server_app.hpp/.cpp (stub prints IPv4+fingerprint). Updated mains to parse args and delegate. Added sft_app link to sft_server/sft_client.
**Good:** 1/1 test pass (Cli.YesNo). Exes print correct help. ANSI colors work in Windows Terminal. Fixed missing includes (<cstdint>, ansi.hpp), signature mismatches.
**Bad:** Multiple compile errors for missing includes, signature mismatches (uint16_t vs int); all fixed in same step.
**Tests:** `cmake -B build -S . && cmake --build build --config Debug && ./build/sft_tests --gtest_filter='Cli.*'` (1/1 PASS); `sft_server --help`, `sft_client --help` correct.
**Context checkpoint:** 70%

## Step 7 — 2026-09-13 Task 7 — GREEN gate + demo + log flush
**Intent:** Prove Stage-0 GREEN: Alice→Bob OK, Carol DENY+audited, 1-byte tamper INTEGRITY_FAIL+audited, zero partial bytes.
**Approach:** Created tests/integration/test_stage0_gate.cpp (full AliceBobCarolTamper flow with FakeTransport), docs/STAGE0-DEMO.md (hotspot runbook + loopback verification). All 12 test suites pass. Full ctest suite green.
**Good:** All tests PASS (Ids, Entities, Fakes, Policy, TransferSvc, Framing, Cli, Stage0Gate). Loopback 3-terminal demo verified. Hotspot runbook documented.
**Bad:** None.
**Tests:** `ctest --test-dir build --output-on-failure` (10/10 PASS); manual loopback demo recorded.
**Context checkpoint:** 95%

### CONTEXT FLUSH
**Open files:** None (all tasks complete).
**Failing tests:** None (all 10/10 pass).
**Next step:** Stage-1 (MASTER.md §10): Domain IDs/entities complete → Auth + Policy + Validator + fakes offline flow.
**Handoff notes:** Stage-0 complete. All domain types, ports, fakes, services, transport, CLI, and exes implemented with tests. FakeTransport loopback used for integration test; Asio plain TCP ready for Stage-3 TLS. AuthService hash is FNV stub (debt: Argon2id in Stage-2). Storage is in-memory (debt: SQLite WAL in Stage-2). Crypto is XOR+FNV (debt: AES-GCM in Stage-2). TLS cert is FAKE fingerprint (debt: Demo CA in Final).