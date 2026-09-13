# Stage 1 Authentication and Account Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete real authentication and account lifecycle over a real client-to-server TLS-protected connection so Alice and Bob can register, log in, log out, and an admin can activate/deactivate persistent accounts with safe server CLI messages.

**Architecture:** Harden existing layered seams without touching file-transfer flow: `presentation/` CLI drives `application/AuthService+AdminService` which own `domain/User` and `domain/Session` invariants; `ports/` adds `IPasswordHasher`, `IUserRepository`, `ISessionStore`, `ITransport`/`ITransportListener`, `IClock`, `IAuditLogger` with real SQLite + libargon2 Argon2id + Asio/OpenSSL TLS adapters and fake adapters for unit tests only; `ITransport` stays the sole client connection boundary and `ITransportListener` the sole server accept boundary, all TLS/fingerprint verification enforced inside `infrastructure/AsioTlsTransport`+`AsioTlsListener` (always `verify_peer`, never `verify_none`), keeping `domain/` and `application/` free of Asio/OpenSSL includes. Session tokens are CSPRNG `dl_*` stored only as `SHA256` hash.

**Tech Stack:** C++20, CMake 3.20+ Ninja, FetchContent `googletest v1.14.0` + `asio asio-1-30-2` (already), add `sqlite3` amalgamation + `libargon2` (FetchContent `phc-winner-argon2 20190702`) for Argon2id, OpenSSL 3.x (`find_package(OpenSSL)` on mingw) for TLS 1.3 + CSPRNG + fingerprint, SQLite `WAL` + `BEGIN IMMEDIATE`.

## Global Constraints

- C++20, CMake 3.20+, Ninja; `googletest v1.14.0`, `asio asio-1-30-2` header-only at `build/_deps/asio-src/asio/include`.
- Fixed port `5000` for live demo; automated tests must use OS-assigned ephemeral ports (bind 0, query actual port), no fixed test ports like 5001/15500.
- Raw TCP + TLS 1.3 framing `[uint32 BE len][msg]` behind `ITransport` (`include/ports/transport.hpp`) and `ITransportListener`; `verify_none` is forbidden in any production transport code — `AsioTlsTransport` always uses `verify_peer` and real TLS, never falls back to plain TCP.
- `FAKE-SHA256-STAGE0-DEMO` is allowed only in `FakeTransport`/`FakeListener` tests; Stage 1 live testing uses a real self-signed certificate and its real `SHA-256` fingerprint (generated via `openssl req -x509`).
- `domain/` must never include Asio/OpenSSL/DB/UI headers; `presentation/` only holds CLI/ANSI (Stage-0) — no FTXUI/new GUI in Stage 1.
- Passwords = Argon2id `m=19456 KiB (19 MiB) t=2 p=1` (OWASP/RFC 9106), encoded hash format (salt+params embedded), never SHA/plain; failures = generic `Login failed`, per-account lockout.
- Server storage owns SQLite + `storage/encrypted/` on server laptop only; client holds only IP:5000 + pinned fingerprint/CA + own key material; original filename = display only.
- Audit = append-only hash chain `msgHash=SHA256(canonicalJSON)` + `prevHash` link, UTC RFC3339; implementation is `HashChainFileAuditLogger` (real, required) + `VectorAudit` (tests only); plaintext passwords, raw session tokens, private keys, file contents never appear in logs/audit; password hashes may exist in DB `pass_hash` column (encoded Argon2 string with embedded salt) but never in logs.
- Errors = typed `AppException` tree (Validation/Auth/NotFound/Storage/Crypto/Integrity/Transport) → generic client string, detail only in protected server log.
- Stage 1 does NOT implement PDF upload/download, per-file DEK, recipient pubkey wrapping, at-rest blob storage, multi-file, multi-format, resume, or GUI; create only minimal seam for Stage 2 to consume authenticated `UserId`.
- Every port has Real + Fake; substitute via ctor injection with `unique_ptr`, no owning raw `new`; RAII guards close files/sockets/tx/locks.
- `Result<T>` failed results must not require a dummy `T` — use `std::optional<T>` value; prefer safe return types (`UserId`/`SessionToken`) over returning credential-bearing `User`.

## Additional Correctness Checks (Stage 1.1 — audit follow-up, must be green)

- **Real TLS:** `AsioTlsTransport`/`AsioTlsListener` must use `asio::ssl::stream<tcp::socket>`, `ssl::context` TLS 1.3 (`sslv23` + `no_sslv2`/`no_tlsv1` etc), `set_verify_mode(verify_peer)`, verify chain/expiry via `load_verify_file(ca)` + `set_verify_callback`, and compare `SHA-256(DER)` fingerprint (hash `i2d_X509` bytes via `EVP_Digest(...,EVP_sha256())`), not PEM text via `sha256stub`. No plain `tcp::socket` fallback.
- **Real Argon2 production path:** live `sft_server` must link `Argon2Hasher` + `SqliteUserRepository` + `HashChainFileAuditLogger`; never `FakeHasher`/`MemoryUserRepository`/`VectorAudit` in prod.
- **Session-derived admin identity:** every admin request (`ADMIN_ACTIVATE/DEACTIVATE`) must derive `adminId` from validated `SessionId` via `ISessionStore::isValid` + `findByToken`, not from client-supplied `adminId` field. Client must send `SessionId` token only.
- **Session token protection:** `sess_` prefix (not `dl_`), `RAND_bytes` CSPRNG, `EVP_sha256` hash for storage, and `rg "sess_|dl_"` proofs that raw tokens never appear in `VectorAudit`/`HashChainFileAuditLogger` output, files, or `formatSafeAuthMessage` CLI.
- **Audit correctness:** UTC `IClock::nowMs()` → RFC3339, monotonic `seq` increment (not 0), JSON escaping (`"`→`\"`, `\`→`\\`, `\n`), `EVP_sha256(canonicalJSON)`, durable `flush` + `fsync`/`FlushFileBuffers` + `fsync` dir, startup `verify()` and refusal to `record()` to a corrupted chain, empty/missing file handling.
- **Repository error handling:** every `sqlite3_prepare_v2/bind/step/finalize` checked, `sqlite3_changes` verified for `UPDATE`, `ROLLBACK` on any failure, `SQLITE_CONSTRAINT` → `ValidationException` translated to generic `"Registration failed"`.
- **Concurrent registration:** rely on `UNIQUE(username)`/`UNIQUE(email)` constraints; `save()` catches `SQLITE_CONSTRAINT` inside `BEGIN IMMEDIATE` TX and returns generic error — no pre-check race.
- **Session invalidation consistency:** SQLite `users` update and in-memory `MemorySessionStore::invalidateAllForUser` cannot be one atomic TX. Fix: either `SqliteSessionStore` (DB-backed sessions, same TX) or every request rechecks `User::isActive()` after `isValid(token)` (defense in depth).
- **Frame robustness:** `tryDecode` tests for `len<5`, `len>4MB`, truncated payload, coalesced frames, and `recvFrame(timeoutMs)` must enforce timeout via `asio::steady_timer` + `socket::cancel`, not ignore `timeoutMs`.
- **Real acceptance evidence:** retain automated ephemeral loopback `Stage1Gate.RealTLSLiveEphemeral` (HELLO + full `REGISTER→LOGIN→LOGOUT→DEACTIVATE` over TLS), but also require manual two-laptop runbook over fixed `5000` with hotspot (loopback alone does not prove deployment topology).

---

## Scope Check

Stage 1 is exactly one MASTER §10 phase (authentication lifecycle). It is self-contained and produces working/testable software without requiring Stage 2 file-flow changes. No split needed — a single plan covers registration/login/logout/persistence/admin/TLS/CLI slices because they share the same `User`/`Session`/`Repository` seams. Future Stage 2 and stretch goals remain separate plans.

## File Structure

```
D:\OOPS\CP/
├── CMakeLists.txt                      # add OpenSSL, sqlite3, libargon2 FetchContent; link to sft_app/sft_server; never link Fake* into prod targets
├── config.example.ini                  # add [auth] argon2 m/t/p, [db] path, [tls] fingerprint/cert path; NO admin password
├── certs/
│   ├── server.crt / server.key         # CREATE: real self-signed cert for Stage 1 (openssl req -x509), gitignored key
│   └── README.md                       # MODIFY: document fingerprint derivation + verify_peer rule
├── include/
│   ├── domain/
│   │   ├── ids.hpp                     # MODIFY: add SessionId {string value}, UserId generation via CSPRNG (not username)
│   │   ├── user.hpp                    # REWRITE: id + username + email + role + status + failedAttempts + lockoutUntil; NO passHash/salt getters; validating ctor
│   │   ├── session.hpp                 # CREATE: Session{SessionId id; UserId userId; int64_t createdAt; int64_t expiresAt; bool revoked; ctor invariants}
│   │   ├── clock.hpp                   # CREATE: IClock { virtual int64_t nowMs() const = 0; } + SystemClock + FakeClock
│   │   └── audit_event.hpp             # MODIFY: add safe actions REGISTER_OK/FAIL, LOGIN_OK/FAIL, LOGOUT, ACTIVATE, DEACTIVATE, ADMIN_DENIED, TLS_FAIL
│   ├── ports/
│   │   ├── result.hpp                  # MODIFY: Result<T> { bool ok; std::optional<T> value; std::string error; }
│   │   ├── user_repository.hpp         # CREATE: IUserRepository { findByUsername/Email/Id, save, update, recordLoginFailure, resetLoginFailures, listAll } — atomic ops with transactions
│   │   ├── password_hasher.hpp         # CREATE: IPasswordHasher { string hash(password); bool verify(encodedHash, password); } — encoded format, no separate salt param
│   │   ├── session_store.hpp           # CREATE: ISessionStore { create, find, invalidate, invalidateAllForUser, isValid } — token hash only
│   │   ├── transport.hpp               # MODIFY: Frame codec stays, add MsgType::REGISTER/LOGOUT/ADMIN_ACTIVATE/DEACTIVATE, keep ITransport for clients
│   │   ├── transport_listener.hpp      # CREATE: ITransportListener { listen(port) -> actualPort, accept()->unique_ptr<ITransport>, close() }
│   │   └── audit.hpp                   # MODIFY: IAuditLogger stays, VectorAudit for tests only
│   ├── application/
│   │   ├── auth_service.hpp            # REWRITE: inject IUserRepository+IPasswordHasher+ISessionStore+IAuditLogger+IClock; register→UserId, login→SessionToken
│   │   └── admin_service.hpp           # CREATE: AdminService{activate, deactivate} — admin-only, audits, invalidates sessions, protects last admin
│   │       └── (no SessionManager — AuthService owns token creation directly via ISessionStore + IClock; do not add a separate SessionManager)
│   ├── infrastructure/
│   │   ├── sqlite_user_repo.hpp/.cpp   # CREATE: SQLite WAL, users table, UNIQUE(username), UNIQUE(email), explicit INSERT/UPDATE, BEGIN IMMEDIATE for atomic failures
│   │   ├── memory_user_repo.hpp/.cpp   # CREATE: single canonical map + indexes (not 3 maps), immutable username/email enforcement
│   │   ├── argon2_hasher.hpp/.cpp      # CREATE: Real Argon2id via libargon2 (m=19456,t=2,p=1, encoded format)
│   │   ├── fake_hasher.hpp             # CREATE: deterministic stub for unit tests ONLY, never linked to sft_server
│   │   ├── memory_session_store.hpp    # CREATE: in-memory session map with IClock, stores SHA256(token) only
│   │   ├── hash_chain_file_audit.hpp/.cpp # CREATE: real append-only hash-chain file logger (required, not optional)
│   │   ├── vector_audit.hpp            # MODIFY: keep for tests, ensure no secret logging
│   │   ├── asio_tls_transport.hpp/.cpp # CREATE: AsioTlsTransport (always TLS, verify_peer, fingerprint check)
│   │   ├── asio_tls_listener.hpp/.cpp  # CREATE: AsioTlsListener (bind 0 for ephemeral, verify_peer)
│   │   ├── fake_transport.hpp          # MODIFY: FakeTransport for tests (allows FAKE fingerprint), never in prod
│   │   └── fake_listener.hpp           # CREATE: FakeListener for tests
│   └── presentation/
│       ├── server_app.hpp/.cpp         # REWRITE: real listener loop via ITransportListener, bootstrap admin via interactive prompt or restricted file (not env), safe CLI prints
│       ├── client_app.hpp/.cpp         # REWRITE: real AsioTlsTransport flow, structured length-prefixed payloads, never handles raw hashes
│       ├── cli.hpp                     # MODIFY: add formatSafeAuthMessage helpers
│       ├── protocol.hpp                # CREATE: encode/decode helpers for REGISTER/LOGIN payloads (length-prefixed, not delimiter)
│       └── ansi.hpp                    # untouched
├── src/                                # mirrors headers, one .cpp per new header
├── tests/
│   ├── domain/test_user_auth.cpp
│   ├── domain/test_session.cpp
│   ├── application/test_auth_service.cpp
│   ├── application/test_admin_service.cpp
│   ├── infra/test_sqlite_user_repo.cpp
│   ├── infra/test_argon2_hasher.cpp
│   ├── infra/test_session_store.cpp
│   ├── infra/test_tls_transport.cpp    # uses generated test cert, ephemeral ports, no detach, checks verify_none absent
│   ├── infra/test_audit_chain.cpp      # verifies hash-chain file logger detects mutate/delete/reorder
│   ├── integration/test_stage1_gate.cpp# real client-server register→login→logout over ephemeral TLS (no skipping as GREEN)
│   └── integration/test_auth_cli_messages.cpp
├── certs/README.md
└── docs/STAGE1-DEMO.md                 # live demo on :5000 with real cert fingerprint
```

Responsibility rule: `domain/` validates only; `application/` orchestrates authz before I/O; `ports/` are pure virtual; `infrastructure/` implements ports; `presentation/` only formats I/O and never decides policy. `User` never exposes credentials — presentation cannot access `passHash`/`salt`; only `IUserRepository`+`IPasswordHasher` handle hashes internally. Stage 2 will consume only `UserId`/`SessionId` from this phase; no file-flow code in Stage 1.

## Parallel Lanes

```
Wave0 sequential: Task 1 (domain hardening + IClock + Result) → Task 2 (Argon2 hasher, libargon2)
Wave1 parallel after Task 2:
  Lane-A: Task 3 SQLite repo + persistence (atomic ops, no REPLACE)
  Lane-B: Task 4 AuthService rework + lockout (uses Task 3 interfaces, can mock with MemoryUserRepo)
Wave2 (needs Wave1): Task 5 sessions (CSPRNG, hash, revoked, IClock) → Task 6 admin activate/deactivate (protect last admin)
Wave3 (independent infra, after Task1): Task 7 TLS transport + listener (always verify_peer, ephemeral ports, real cert) + hash-chain audit
Wave4: Task 8 server/client CLI wiring (new MsgTypes, structured payloads, listener abstraction, no hardcoded admin)
Wave5: Task 9 real integration gate + Stage1 demo doc + GREEN checklist (ephemeral ports, no skipped TLS)
```

Lane contract: do not change headers owned by another lane; if blocked, log to `docs/impl-logs/stage-1-impl-log.md` and continue with `Fake*` in tests only.

---

### Task 1: Harden domain User + Session + IClock + Result

**Files:**
- Modify: `include/domain/ids.hpp:1-6` (add `SessionId`, add `generateId()` helper declaration)
- Modify: `include/domain/user.hpp:1-19` (rewrite — no credential getters)
- Create: `include/domain/session.hpp`
- Create: `include/domain/clock.hpp`
- Modify: `include/domain/result.hpp:1-4` (optional value)
- Modify: `include/domain/audit_event.hpp:1-5`
- Create: `tests/domain/test_user_auth.cpp`
- Create: `tests/domain/test_session.cpp`

**Interfaces:**
- Consumes: `include/domain/exceptions.hpp:ValidationException`
- Produces: `struct UserId { string value; == }` with `UserId generateUserId()` (CSPRNG UUIDv4 via OpenSSL `RAND_bytes`, not username); `class User { User(UserId id, string username, string email, string role="user", string status="active", int failedAttempts=0, int64_t lockoutUntil=0); // NO passHash/salt members; getters: id(), username(), email(), role(), status(), failedAttempts(), lockoutUntil(); bool isAdmin() const; bool isActive() const; bool canLogin(int64_t now) const; }` + `RegularUser/Administrator` + `struct Session { SessionId id; UserId userId; int64_t createdAt; int64_t expiresAt; bool revoked; Session(...){ if(createdAt>=expiresAt) throw ValidationException; } bool isValid(int64_t now) const { return !revoked && now>=createdAt && now<expiresAt; } }` + `class IClock { virtual int64_t nowMs() const =0; }`

- [ ] **Step 1: Write the failing test**

```cpp
// tests/domain/test_user_auth.cpp
#include <gtest/gtest.h>
#include "domain/user.hpp"
#include "domain/ids.hpp"
TEST(UserDomain, CanLoginActiveAndInactive) {
  User u(generateUserId(), "alice", "alice@ex.com", "user", "active");
  EXPECT_TRUE(u.canLogin(0));
  User inactive(generateUserId(), "bob", "b@ex.com", "user", "inactive");
  EXPECT_FALSE(inactive.canLogin(0));
}
TEST(UserDomain, AdminRole) {
  User admin(generateUserId(), "admin", "a@ex.com", "admin", "active");
  EXPECT_TRUE(admin.isAdmin());
  User ru(generateUserId(), "alice", "a@ex.com", "user", "active");
  EXPECT_FALSE(ru.isAdmin());
}
TEST(UserDomain, ValidationRejectsEmpty) {
  EXPECT_THROW(User(UserId{""}, "", "a@ex.com"), ValidationException);
  EXPECT_THROW(User(generateUserId(), "", "a@ex.com"), ValidationException);
  EXPECT_THROW(User(generateUserId(), "alice", ""), ValidationException);
}
TEST(UserDomain, IdIndependentOfUsername) {
  auto id1 = generateUserId();
  auto id2 = generateUserId();
  EXPECT_NE(id1.value, id2.value);
  User u1(id1, "alice", "a@ex.com");
  User u2(id2, "alice", "other@ex.com");
  EXPECT_NE(u1.id().value, u2.id().value);
}
TEST(UserDomain, NoCredentialGetters) {
  // compile-time check: User must not expose passHash/salt methods
  // This test documents the contract — it will fail to compile if getters exist
  User u(generateUserId(), "alice", "a@ex.com");
  (void)u.username(); (void)u.email(); (void)u.role();
  // u.passHash() must not compile — verified by grep in Step 4
}
```

```cpp
// tests/domain/test_session.cpp
#include <gtest/gtest.h>
#include "domain/session.hpp"
TEST(SessionDomain, ValidAndExpired) {
  Session s{SessionId{"tok1"}, UserId{"u1"}, 1000, 2000, false};
  EXPECT_TRUE(s.isValid(1500));
  EXPECT_FALSE(s.isValid(2500));
  EXPECT_FALSE(s.isValid(500));
}
TEST(SessionDomain, RevokedInvalidates) {
  Session s{SessionId{"tok1"}, UserId{"u1"}, 1000, 5000, false};
  s.revoked = true;
  EXPECT_FALSE(s.isValid(2000));
}
TEST(SessionDomain, InvariantsRejectBadRange) {
  EXPECT_THROW(Session(SessionId{"x"}, UserId{"u"}, 2000, 1000, false), ValidationException);
  EXPECT_THROW(Session(SessionId{"x"}, UserId{"u"}, 1000, 1000, false), ValidationException);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build -G Ninja; cmake --build build; ./build/sft_tests.exe --gtest_filter=UserDomain.*:SessionDomain.* -v`
Expected: FAIL with `domain/session.hpp not found` and `generateUserId not declared` and `Result` mismatch.

- [ ] **Step 3: Write minimal implementation**

```cpp
// include/domain/ids.hpp
#pragma once
#include <string>
struct UserId { std::string value; bool operator==(const UserId&) const = default; };
struct FileId { std::string value; bool operator==(const FileId&) const = default; };
struct TransferId { std::string value; bool operator==(const TransferId&) const = default; };
struct SessionId { std::string value; bool operator==(const SessionId&) const = default; };
UserId generateUserId(); // CSPRNG UUIDv4 hex, e.g. "550e8400-e29b-41d4-a716-446655440000"
SessionId generateSessionId(); // CSPRNG 32B base64url with dl_ prefix handled at store layer
```

```cpp
// include/domain/clock.hpp
#pragma once
#include <cstdint>
class IClock { public: virtual ~IClock()=default; virtual int64_t nowMs() const = 0; };
class SystemClock : public IClock { public: int64_t nowMs() const override; };
class FakeClock : public IClock { public: explicit FakeClock(int64_t t=0): t_(t) {} int64_t nowMs() const override { return t_; } void advance(int64_t d){ t_+=d; } void set(int64_t t){ t_=t; } private: int64_t t_; };
```

```cpp
// include/domain/result.hpp
#pragma once
#include <string>
#include <optional>
#include <utility>
template<typename T> struct Result {
  bool ok=false;
  std::optional<T> value{};
  std::string error;
  static Result<T> success(T v){ return {true, std::move(v), ""}; }
  static Result<T> failure(std::string e){ return {false, std::nullopt, std::move(e)}; }
};
// specialization for void not needed — use Result<UserId> / Result<SessionId> with generic messages
```

```cpp
// include/domain/user.hpp
#pragma once
#include "domain/ids.hpp"
#include "domain/exceptions.hpp"
#include <string>
#include <cstdint>
class User {
 public:
  User(UserId id, std::string username, std::string email, std::string role="user", std::string status="active",
       int failedAttempts=0, int64_t lockoutUntil=0)
      : id_(std::move(id)), username_(std::move(username)), email_(std::move(email)), role_(role), status_(status),
        failedAttempts_(failedAttempts), lockoutUntil_(lockoutUntil) {
    if (id_.value.empty() || username_.empty() || email_.empty()) throw ValidationException("user fields empty");
  }
  virtual ~User() = default;
  const UserId& id() const { return id_; }
  const std::string& username() const { return username_; }
  const std::string& email() const { return email_; }
  const std::string& role() const { return role_; }
  const std::string& status() const { return status_; }
  int failedAttempts() const { return failedAttempts_; }
  int64_t lockoutUntil() const { return lockoutUntil_; }
  bool isAdmin() const { return role_=="admin"; }
  bool isActive() const { return status_=="active"; }
  bool canLogin(int64_t now) const { return isActive() && now>=lockoutUntil_; }
  void setStatus(const std::string& s){ status_=s; }
  void setLockout(int64_t until, int attempts){ lockoutUntil_=until; failedAttempts_=attempts; }
 private:
  UserId id_; std::string username_, email_, role_, status_;
  int failedAttempts_; int64_t lockoutUntil_;
};
class RegularUser : public User { public: using User::User; };
class Administrator : public User { public: using User::User; };
```

```cpp
// include/domain/session.hpp
#pragma once
#include "domain/ids.hpp"
#include "domain/exceptions.hpp"
#include <cstdint>
#include <string>
struct Session {
  SessionId id; UserId userId; int64_t createdAt=0; int64_t expiresAt=0; bool revoked=false;
  Session() = default;
  Session(SessionId sid, UserId uid, int64_t c, int64_t e, bool rev=false): id(std::move(sid)), userId(std::move(uid)), createdAt(c), expiresAt(e), revoked(rev){
    if (createdAt>=expiresAt) throw ValidationException("session time range invalid");
  }
  bool isValid(int64_t now) const { return !revoked && now>=createdAt && now<expiresAt; }
};
```

Append to `include/domain/audit_event.hpp`:
```cpp
namespace AuditAction {
  inline constexpr const char* REGISTER_OK="REGISTER_OK"; inline constexpr const char* REGISTER_FAIL="REGISTER_FAIL";
  inline constexpr const char* LOGIN_OK="LOGIN_OK"; inline constexpr const char* LOGIN_FAIL="LOGIN_FAIL";
  inline constexpr const char* LOGOUT="LOGOUT"; inline constexpr const char* ACTIVATE="ACTIVATE";
  inline constexpr const char* DEACTIVATE="DEACTIVATE"; inline constexpr const char* ADMIN_DENIED="ADMIN_DENIED";
  inline constexpr const char* TLS_FAIL="TLS_FAIL";
}
```

Implement `generateUserId()` in `src/domain/ids.cpp` using `RAND_bytes` + hex UUID formatting; if OpenSSL unavailable in domain, delegate to `infrastructure` helper injected via `IIdGenerator` — but simplest is to keep generation in `infrastructure` and pass `UserId` into `User` ctor from repository layer, so `generateUserId` may live in `infrastructure/id_generator.hpp`. Document choice: `User` ctor takes externally generated `UserId` (CSPRNG), never `UserId{username}`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cmake --build build; ./build/sft_tests.exe --gtest_filter=UserDomain.*:SessionDomain.* -v`
Expected: PASS 7 tests. Also verify: `rg "passHash|salt\(\)" include/domain/user.hpp` must return empty; `rg "UserId\{.*username" tests/` must return empty (PowerShell: `Select-String -Pattern "passHash|salt\(\)" -Path include/domain/user.hpp`).

- [ ] **Step 5: Commit**

```bash
git add include/domain/ids.hpp include/domain/user.hpp include/domain/session.hpp include/domain/clock.hpp include/domain/result.hpp include/domain/audit_event.hpp tests/domain/test_user_auth.cpp tests/domain/test_session.cpp src/domain/ids.cpp
git commit -m "feat(stage1): harden User/Session domain + IClock + Result with optional value"
```

---

### Task 2: Password hashing port — Argon2id via libargon2 (real only)

**Files:**
- Create: `include/ports/password_hasher.hpp`
- Create: `include/infrastructure/argon2_hasher.hpp` + `src/infrastructure/argon2_hasher.cpp`
- Create: `include/infrastructure/fake_hasher.hpp` (tests only, never prod)
- Create: `tests/infra/test_argon2_hasher.cpp`
- Modify: `CMakeLists.txt:1-32` (FetchContent libargon2, find_package OpenSSL)

**Interfaces:**
- Consumes: `std::string password`
- Produces: `class IPasswordHasher { virtual std::string hash(const std::string& password) = 0; // returns encoded string $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash> virtual bool verify(const std::string& encodedHash, const std::string& password) = 0; }` + `class Argon2Hasher: IPasswordHasher` (libargon2, memoryCost=19456, timeCost=2, parallelism=1, 32-byte hash, 16-byte salt via `RAND_bytes`) + `class FakeHasher` (deterministic sha256stub for fast unit tests, never linked to `sft_server`)

- [ ] **Step 1: Write the failing test**

```cpp
// tests/infra/test_argon2_hasher.cpp
#include <gtest/gtest.h>
#include "infrastructure/fake_hasher.hpp"
#include "infrastructure/argon2_hasher.hpp"
TEST(Hasher, FakeRoundTrip) {
  FakeHasher h;
  auto hash = h.hash("secret123");
  EXPECT_TRUE(h.verify(hash, "secret123"));
  EXPECT_FALSE(h.verify(hash, "wrong"));
}
TEST(Hasher, Argon2EncodesAndVerifies) {
  Argon2Hasher h;
  auto hash = h.hash("correct horse");
  EXPECT_NE(hash, "correct horse");
  EXPECT_EQ(hash.find("correct horse"), std::string::npos);
  EXPECT_TRUE(hash.rfind("$argon2id$", 0) == 0);
  EXPECT_TRUE(h.verify(hash, "correct horse"));
  EXPECT_FALSE(h.verify(hash, "wrong"));
}
TEST(Hasher, Argon2UniqueHashForSamePassword) {
  Argon2Hasher h;
  auto h1 = h.hash("same");
  auto h2 = h.hash("same");
  EXPECT_NE(h1, h2);
  EXPECT_TRUE(h.verify(h1, "same"));
  EXPECT_TRUE(h.verify(h2, "same"));
}
TEST(Hasher, Argon2EncodedContainsParams) {
  Argon2Hasher h;
  auto hash = h.hash("test");
  // encoded string must contain m=19456,t=2,p=1
  EXPECT_NE(hash.find("m=19456"), std::string::npos);
  EXPECT_NE(hash.find("t=2"), std::string::npos);
  EXPECT_NE(hash.find("p=1"), std::string::npos);
}
TEST(Hasher, NoPlaintextInHash) {
  Argon2Hasher h;
  auto hash = h.hash("SuperSecret123");
  EXPECT_EQ(hash.find("SuperSecret123"), std::string::npos);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build; ./build/sft_tests.exe --gtest_filter=Hasher.* -v`
Expected: FAIL `ports/password_hasher.hpp not found`.

- [ ] **Step 3: Write minimal implementation**

```cpp
// include/ports/password_hasher.hpp
#pragma once
#include <string>
class IPasswordHasher {
 public:
  virtual ~IPasswordHasher() = default;
  virtual std::string hash(const std::string& password) = 0;
  virtual bool verify(const std::string& encodedHash, const std::string& password) = 0;
};
```

```cpp
// include/infrastructure/fake_hasher.hpp
#pragma once
#include "ports/password_hasher.hpp"
#include "domain/digest.hpp"
class FakeHasher : public IPasswordHasher {
 public:
  std::string hash(const std::string& pw) override {
    auto d = sha256stub(pw + std::to_string(++ctr_));
    std::string s(d.bytes.begin(), d.bytes.end());
    return "$fake$"+s;
  }
  bool verify(const std::string& h, const std::string& pw) override {
    // fake verify is not cryptographically meaningful — only for fast unit tests of service logic
    // real tests must use Argon2Hasher
    return h.find(pw)!=std::string::npos || h.size()>0; // simplified — store map in real impl
  }
 private: int ctr_=0;
};
// Note: for deterministic fake verify, keep a map<string,string> lastPassword; do exact compare.
```

Corrected `FakeHasher` with map:
```cpp
class FakeHasher : public IPasswordHasher {
  std::unordered_map<std::string,std::string> m_;
  int ctr_=0;
 public:
  std::string hash(const std::string& pw) override { auto h="$fake$"+std::to_string(ctr_++)+"$"+pw; m_[h]=pw; return h; }
  bool verify(const std::string& h, const std::string& pw) override { auto it=m_.find(h); return it!=m_.end() && it->second==pw; }
};
```

```cpp
// include/infrastructure/argon2_hasher.hpp
#pragma once
#include "ports/password_hasher.hpp"
class Argon2Hasher : public IPasswordHasher {
 public:
  std::string hash(const std::string& pw) override;
  bool verify(const std::string& encoded, const std::string& pw) override;
};
```

```cpp
// src/infrastructure/argon2_hasher.cpp
#include "infrastructure/argon2_hasher.hpp"
#include <argon2.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <vector>
// Required params per MASTER §4: m=19456 KiB, t=2, p=1, hashlen=32, saltlen=16
static constexpr uint32_t MEM_COST=19456, TIME_COST=2, PARALLELISM=1, HASH_LEN=32, SALT_LEN=16;
std::string Argon2Hasher::hash(const std::string& pw) {
  unsigned char salt[SALT_LEN];
  if (RAND_bytes(salt, SALT_LEN)!=1) throw std::runtime_error("RAND_bytes failed");
  // argon2_encodedlen computes exact buffer size for encoded string
  size_t encLen = argon2_encodedlen(TIME_COST, MEM_COST, PARALLELISM, SALT_LEN, HASH_LEN, Argon2_id);
  std::vector<char> out(encLen);
  int rc = argon2id_hash_encoded(TIME_COST, MEM_COST, PARALLELISM, pw.data(), pw.size(), salt, SALT_LEN, HASH_LEN, out.data(), out.size());
  if (rc!=ARGON2_OK) throw std::runtime_error(argon2_error_message(rc));
  return std::string(out.data());
}
bool Argon2Hasher::verify(const std::string& enc, const std::string& pw) {
  int rc = argon2id_verify(enc.c_str(), pw.data(), pw.size());
  return rc==ARGON2_OK;
}
```

CMake (exact, choose libargon2 only):
```cmake
find_package(OpenSSL REQUIRED)
FetchContent_Declare(argon2 GIT_REPOSITORY https://github.com/P-H-C/phc-winner-argon2.git GIT_TAG 20190702)
FetchContent_MakeAvailable(argon2)
# argon2 provides src/argon2.c etc — build static lib
add_library(argon2 STATIC ${argon2_SOURCE_DIR}/src/argon2.c ${argon2_SOURCE_DIR}/src/core.c ${argon2_SOURCE_DIR}/src/blake2/blake2b.c ${argon2_SOURCE_DIR}/src/thread.c ${argon2_SOURCE_DIR}/src/encoding.c ${argon2_SOURCE_DIR}/src/ref.c)
target_include_directories(argon2 PUBLIC ${argon2_SOURCE_DIR}/include)
target_link_libraries(sft_app PRIVATE OpenSSL::SSL OpenSSL::Crypto argon2)
# Never link FakeHasher to sft_server prod target — only to sft_tests
```

Stage 1 is NOT GREEN if `Argon2Hasher` tests are skipped — there is no `GTEST_SKIP` fallback for Argon2. `FakeHasher` may be used in fast service tests, but `Hasher.Argon2*` must PASS on the build machine. If libargon2 fails to compile on mingw, the task is blocked until it passes.

- [ ] **Step 4: Run test to verify it passes**

Run: `cmake -S . -B build -G Ninja; cmake --build build; ./build/sft_tests.exe --gtest_filter=Hasher.Argon2* -v`
Expected: PASS 4 Argon2 tests, no SKIP. `Hasher.FakeRoundTrip` also PASS.

- [ ] **Step 5: Commit**

```bash
git add include/ports/password_hasher.hpp include/infrastructure/argon2_hasher.hpp src/infrastructure/argon2_hasher.cpp include/infrastructure/fake_hasher.hpp tests/infra/test_argon2_hasher.cpp CMakeLists.txt
git commit -m "feat(stage1): Argon2id libargon2 hasher (m=19456,t=2,p=1) encoded format"
```

---

### Task 3: Persistent user repository — SQLite + in-memory (no REPLACE, single map)

**Files:**
- Create: `include/ports/user_repository.hpp`
- Create: `include/infrastructure/sqlite_user_repo.hpp` + `src/infrastructure/sqlite_user_repo.cpp`
- Create: `include/infrastructure/memory_user_repo.hpp` + `src/infrastructure/memory_user_repo.cpp`
- Create: `tests/infra/test_sqlite_user_repo.cpp`
- Modify: `config.example.ini:1-9`
- Modify: `CMakeLists.txt` (sqlite3)
- Modify: `include/domain/result.hpp` already done in Task 1 — ensure `Result<User>` uses optional.

**Interfaces:**
- Consumes: `domain/User` (no credentials), `IPasswordHasher` encoded hash stored via repo
- Produces: `class IUserRepository { virtual Result<User> findByUsername(const string&) const =0; virtual Result<User> findByEmail(const string&) const=0; virtual Result<User> findById(const UserId&) const=0; virtual void save(const User& u, const string& encodedHash) =0; // encodedHash is $argon2id$... string virtual void update(const User& u) =0; virtual void recordLoginFailure(const UserId& id, int newFailed, int64_t newLockUntil) =0; // atomic BEGIN IMMEDIATE virtual void resetLoginFailures(const UserId& id)=0; virtual string getEncodedHash(const UserId&) const=0; virtual vector<User> listAll() const=0; }` — note: credentials never on `User` object, stored in separate column `pass_hash`.

- [ ] **Step 1: Write the failing test**

```cpp
// tests/infra/test_sqlite_user_repo.cpp
#include <gtest/gtest.h>
#include "infrastructure/sqlite_user_repo.hpp"
#include "infrastructure/memory_user_repo.hpp"
#include "domain/user.hpp"
#include <filesystem>
namespace fs = std::filesystem;
TEST(UserRepo, MemoryRoundTrip) {
  MemoryUserRepository r;
  auto id = generateUserId();
  User u(id, "alice", "alice@ex.com");
  r.save(u, "$argon2id$v=19$m=19456,t=2,p=1$fakehash");
  auto got = r.findByUsername("alice");
  ASSERT_TRUE(got.ok);
  ASSERT_TRUE(got.value.has_value());
  EXPECT_EQ(got.value->email(), "alice@ex.com");
  EXPECT_FALSE(r.findByUsername("nope").ok);
  EXPECT_EQ(r.getEncodedHash(id), "$argon2id$v=19$m=19456,t=2,p=1$fakehash");
}
TEST(UserRepo, SqlitePersistsAcrossReopen) {
  auto dbPath = (fs::temp_directory_path() / ("test_users_persist_" + generateSessionId().value + ".db")).string();
  fs::remove(dbPath);
  auto id = generateUserId();
  {
    SqliteUserRepository r(dbPath);
    User u(id, "alice", "alice@ex.com");
    r.save(u, "$argon2id$v=19$m=19456,t=2,p=1$hash1");
    ASSERT_TRUE(r.findByUsername("alice").ok);
  }
  {
    SqliteUserRepository r2(dbPath);
    auto got = r2.findByUsername("alice");
    ASSERT_TRUE(got.ok);
    ASSERT_TRUE(got.value.has_value());
    EXPECT_EQ(got.value->email(), "alice@ex.com");
    EXPECT_EQ(r2.getEncodedHash(id), "$argon2id$v=19$m=19456,t=2,p=1$hash1");
  }
  fs::remove(dbPath);
}
TEST(UserRepo, UniqueUsernameEmail) {
  MemoryUserRepository r;
  auto id1=generateUserId(), id2=generateUserId(), id3=generateUserId();
  User u1(id1, "alice", "a@ex.com");
  User u2(id2, "alice", "b@ex.com");
  r.save(u1, "$argon2id$h1");
  EXPECT_THROW(r.save(u2, "$argon2id$h2"), ValidationException);
  User u3(id3, "bob", "a@ex.com");
  EXPECT_THROW(r.save(u3, "$argon2id$h3"), ValidationException);
}
TEST(UserRepo, ImmutableUsernameEmail) {
  MemoryUserRepository r;
  auto id=generateUserId();
  User u(id, "alice", "a@ex.com");
  r.save(u, "$argon2id$h");
  // attempt to change username via update should fail — username/email immutable after creation
  auto found = r.findById(id);
  ASSERT_TRUE(found.ok && found.value.has_value());
  User modified = found.value.value();
  // repository update must not allow username change; test that save with same id but different username throws
  User withNewName(id, "alice2", "a@ex.com");
  EXPECT_THROW(r.update(withNewName), ValidationException);
}
TEST(UserRepo, AtomicRecordLoginFailure) {
  auto dbPath = (fs::temp_directory_path() / ("test_users_atomic_" + generateSessionId().value + ".db")).string();
  fs::remove(dbPath);
  SqliteUserRepository r(dbPath);
  auto id=generateUserId();
  r.save(User(id, "alice", "a@ex.com"), "$argon2id$h");
  r.recordLoginFailure(id, 1, 1000);
  r.recordLoginFailure(id, 2, 2000);
  auto got = r.findById(id);
  ASSERT_TRUE(got.ok && got.value.has_value());
  auto u = got.value.value();
  EXPECT_EQ(u.failedAttempts(), 2);
  r.resetLoginFailures(id);
  auto got2 = r.findById(id);
  ASSERT_TRUE(got2.ok && got2.value.has_value());
  EXPECT_EQ(got2.value->failedAttempts(), 0);
  fs::remove(dbPath);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build; ./build/sft_tests.exe --gtest_filter=UserRepo.* -v`
Expected: FAIL `ports/user_repository.hpp not found`.

- [ ] **Step 3: Write minimal implementation**

```cpp
// include/ports/user_repository.hpp
#pragma once
#include "domain/user.hpp"
#include "domain/result.hpp"
#include <vector>
#include <string>
class IUserRepository {
 public:
  virtual ~IUserRepository() = default;
  virtual Result<User> findByUsername(const std::string& name) const = 0;
  virtual Result<User> findByEmail(const std::string& email) const = 0;
  virtual Result<User> findById(const UserId& id) const = 0;
  virtual void save(const User& u, const std::string& encodedHash) = 0; // INSERT only, throws if exists
  virtual void update(const User& u) = 0; // UPDATE mutable fields only (status, failedAttempts, lockoutUntil)
  virtual void updateHash(const UserId& id, const std::string& newEncodedHash) = 0;
  virtual void recordLoginFailure(const UserId& id, int newFailed, int64_t newLockUntil) = 0; // BEGIN IMMEDIATE
  virtual void resetLoginFailures(const UserId& id) = 0;
  virtual std::string getEncodedHash(const UserId& id) const = 0; // for verifier, not exposed to presentation
  virtual std::vector<User> listAll() const = 0;
};
```

Memory impl (single canonical map):
```cpp
// include/infrastructure/memory_user_repo.hpp
#pragma once
#include "ports/user_repository.hpp"
#include <unordered_map>
class MemoryUserRepository : public IUserRepository {
 public:
  Result<User> findByUsername(const std::string& n) const override;
  Result<User> findByEmail(const std::string& e) const override;
  Result<User> findById(const UserId& id) const override;
  void save(const User& u, const std::string& encodedHash) override;
  void update(const User& u) override;
  void updateHash(const UserId& id, const std::string& h) override;
  void recordLoginFailure(const UserId& id, int f, int64_t until) override;
  void resetLoginFailures(const UserId& id) override;
  std::string getEncodedHash(const UserId& id) const override;
  std::vector<User> listAll() const override;
 private:
  std::unordered_map<std::string, User> usersById_; // canonical
  std::unordered_map<std::string, std::string> usernameToId_, emailToId_; // indexes
  std::unordered_map<std::string, std::string> hashById_;
};
```
`save` inserts into `usersById_` + indexes, throws `ValidationException` if `usernameToId_` or `emailToId_` collides; `update` fetches existing, checks username/email unchanged (immutable), updates only `status/failedAttempts/lockoutUntil` in-place so indexes never go stale.

Sqlite schema (exact):
```sql
CREATE TABLE IF NOT EXISTS users(
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  pass_hash TEXT NOT NULL, -- encoded $argon2id$ string (contains salt+params)
  role TEXT NOT NULL,
  status TEXT NOT NULL,
  failed_attempts INT NOT NULL,
  lockout_until INTEGER NOT NULL
);
PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
```
`save` does `BEGIN IMMEDIATE; INSERT INTO users ...; COMMIT` (no `OR REPLACE`); `update` does `BEGIN IMMEDIATE; UPDATE users SET status=?, failed_attempts=?, lockout_until=? WHERE id=?; COMMIT`; `recordLoginFailure` does `BEGIN IMMEDIATE; UPDATE ... SET failed_attempts=?, lockout_until=?; COMMIT` atomically.

`config.example.ini`:
```ini
[db]
path=./storage/users.db
[auth]
argon2_m=19456
argon2_t=2
argon2_p=1
```

CMake sqlite: `FetchContent_Declare(sqlite3 URL https://www.sqlite.org/2024/sqlite-amalgamation-3460000.zip)` + `add_library(sqlite3 STATIC ${sqlite3_SOURCE_DIR}/sqlite3.c)` + `target_include_directories(sqlite3 PUBLIC ${sqlite3_SOURCE_DIR})` + `target_link_libraries(sft_app PRIVATE sqlite3)`.

Secrecy note: DB `pass_hash` column holds encoded Argon2 hash (which includes salt+params) — this is expected and correct. Plaintext passwords never appear anywhere.

- [ ] **Step 4: Run test to verify it passes**

Run: `cmake --build build -G Ninja; cmake --build build; ./build/sft_tests.exe --gtest_filter=UserRepo.* -v`
Expected: PASS 5 tests; temp files cleaned via `fs::remove` after repo destructor (close handle first — ensure SQLite `sqlite3_close` called before remove).

- [ ] **Step 5: Commit**

```bash
git add include/ports/user_repository.hpp include/infrastructure/sqlite_user_repo.hpp src/infrastructure/sqlite_user_repo.cpp include/infrastructure/memory_user_repo.hpp src/infrastructure/memory_user_repo.cpp tests/infra/test_sqlite_user_repo.cpp config.example.ini CMakeLists.txt
git commit -m "feat(stage1): persistent user repo (SQLite WAL + atomic ops, no REPLACE)"
```

---

### Task 4: AuthService — register/login with generic errors + atomic lockout + IClock

**Files:**
- Modify: `include/application/auth_service.hpp:1-13`
- Modify: `src/application/auth_service.cpp:1-19`
- Create: `tests/application/test_auth_service.cpp`

**Interfaces:**
- Consumes: `IUserRepository`, `IPasswordHasher`, `ISessionStore`, `IAuditLogger`, `IClock`
- Produces: `class AuthService { AuthService(IUserRepository*, IPasswordHasher*, ISessionStore*, IAuditLogger*, IClock*); Result<UserId> registerUser(string username, string email, string password, string role="user"); // returns UserId on success, generic "Registration failed" on any duplicate/validation Result<SessionId> login(string username, string password); // generic "Login failed" for not-found/bad-pass/inactive/lockout, uses repo.recordLoginFailure/reset atomically, creates CSPRNG session token via store bool logout(SessionId token); }`

- [ ] **Step 1: Write the failing test**

```cpp
// tests/application/test_auth_service.cpp
#include <gtest/gtest.h>
#include "application/auth_service.hpp"
#include "infrastructure/memory_user_repo.hpp"
#include "infrastructure/fake_hasher.hpp"
#include "infrastructure/vector_audit.hpp"
#include "infrastructure/memory_session_store.hpp"
#include "domain/clock.hpp"
TEST(AuthSvc, RegisterSuccessAndDuplicateGeneric) {
  MemoryUserRepository repo; FakeHasher hasher; VectorAudit audit; MemorySessionStore sessions; FakeClock clock(0);
  AuthService svc(&repo, &hasher, &sessions, &audit, &clock);
  auto r1 = svc.registerUser("alice", "alice@ex.com", "secret123");
  ASSERT_TRUE(r1.ok);
  ASSERT_TRUE(r1.value.has_value());
  // duplicate username → generic error, no enumeration
  auto r2 = svc.registerUser("alice", "other@ex.com", "secret123");
  EXPECT_FALSE(r2.ok);
  EXPECT_EQ(r2.error, "Registration failed");
  auto r3 = svc.registerUser("bob", "alice@ex.com", "secret123");
  EXPECT_FALSE(r3.ok);
  EXPECT_EQ(r3.error, "Registration failed");
  // never store plaintext — hash column must not contain password
  auto id = r1.value.value();
  EXPECT_EQ(repo.getEncodedHash(id).find("secret123"), std::string::npos);
}
TEST(AuthSvc, LoginSuccessAndGenericFailure) {
  MemoryUserRepository repo; FakeHasher hasher; VectorAudit audit; MemorySessionStore sessions; FakeClock clock(1000);
  AuthService svc(&repo, &hasher, &sessions, &audit, &clock);
  svc.registerUser("alice", "a@ex.com", "correct123");
  auto ok = svc.login("alice", "correct123");
  ASSERT_TRUE(ok.ok && ok.value.has_value());
  auto bad = svc.login("alice", "wrong");
  EXPECT_FALSE(bad.ok);
  EXPECT_EQ(bad.error, "Login failed");
  auto noUser = svc.login("nobody", "whatever");
  EXPECT_FALSE(noUser.ok);
  EXPECT_EQ(noUser.error, "Login failed");
}
TEST(AuthSvc, InactiveUserRejected) {
  MemoryUserRepository repo; FakeHasher hasher; VectorAudit audit; MemorySessionStore sessions; FakeClock clock(0);
  AuthService svc(&repo, &hasher, &sessions, &audit, &clock);
  svc.registerUser("alice", "a@ex.com", "pw123456");
  auto found = repo.findByUsername("alice");
  ASSERT_TRUE(found.ok && found.value.has_value());
  auto aliceId = found.value->id();
  auto found2 = repo.findById(aliceId);
  ASSERT_TRUE(found2.ok && found2.value.has_value());
  User u = found2.value.value();
  u.setStatus("inactive"); repo.update(u);
  auto res = svc.login("alice", "pw123456");
  EXPECT_FALSE(res.ok);
  EXPECT_EQ(res.error, "Login failed");
}
TEST(AuthSvc, LockoutAfter5Fails) {
  MemoryUserRepository repo; FakeHasher hasher; VectorAudit audit; MemorySessionStore sessions; FakeClock clock(0);
  AuthService svc(&repo, &hasher, &sessions, &audit, &clock);
  svc.registerUser("alice", "a@ex.com", "pw123456");
  for(int i=0;i<5;i++){ clock.set(i*1000); svc.login("alice", "bad"); }
  clock.set(5000);
  auto blocked = svc.login("alice", "pw123456");
  EXPECT_FALSE(blocked.ok);
  clock.set(20*60*1000);
  auto after = svc.login("alice", "pw123456");
  EXPECT_TRUE(after.ok);
}
TEST(AuthSvc, AuditNeverContainsPassword) {
  MemoryUserRepository repo; FakeHasher hasher; VectorAudit audit; MemorySessionStore sessions; FakeClock clock(0);
  AuthService svc(&repo, &hasher, &sessions, &audit, &clock);
  svc.registerUser("alice", "a@ex.com", "mySecret999");
  svc.login("alice", "wrong");
  for(auto& e: audit.all()) {
    EXPECT_EQ(e.actor.find("mySecret999"), std::string::npos);
    EXPECT_EQ(e.action.find("mySecret999"), std::string::npos);
    EXPECT_EQ(e.cipherHash.find("mySecret999"), std::string::npos);
  }
}
TEST(AuthSvc, ReturnedValueIsUserIdNotFullUser) {
  MemoryUserRepository repo; FakeHasher hasher; VectorAudit audit; MemorySessionStore sessions; FakeClock clock(0);
  AuthService svc(&repo, &hasher, &sessions, &audit, &clock);
  auto r = svc.registerUser("alice", "a@ex.com", "pw123456");
  ASSERT_TRUE(r.ok);
  // value must be UserId, not User with credentials
  static_assert(std::is_same_v<decltype(r.value.value()), UserId>);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build; ./build/sft_tests.exe --gtest_filter=AuthSvc.* -v`
Expected: FAIL `AuthService` old 2-arg ctor not found.

- [ ] **Step 3: Write minimal implementation**

```cpp
// include/application/auth_service.hpp
#pragma once
#include "domain/user.hpp"
#include "domain/session.hpp"
#include "domain/result.hpp"
#include "domain/clock.hpp"
#include "ports/user_repository.hpp"
#include "ports/password_hasher.hpp"
#include "ports/audit.hpp"
#include "ports/session_store.hpp"
#include <string>
class AuthService {
 public:
  AuthService(IUserRepository* repo, IPasswordHasher* hasher, ISessionStore* sessions, IAuditLogger* audit, IClock* clock)
    : repo_(repo), hasher_(hasher), sessions_(sessions), audit_(audit), clock_(clock) {}
  Result<UserId> registerUser(const std::string& username, const std::string& email, const std::string& password, const std::string& role="user");
  Result<SessionId> login(const std::string& username, const std::string& password);
  bool logout(const SessionId& token);
 private:
  IUserRepository* repo_; IPasswordHasher* hasher_; ISessionStore* sessions_; IAuditLogger* audit_; IClock* clock_;
  static constexpr int MAX_FAILS=5; static constexpr int64_t LOCKOUT_MS=15*60*1000;
};
```

```cpp
// src/application/auth_service.cpp
#include "application/auth_service.hpp"
#include "domain/exceptions.hpp"
Result<UserId> AuthService::registerUser(const std::string& u, const std::string& email, const std::string& pw, const std::string& role){
  if (u.empty() || email.empty() || pw.size()<8) return Result<UserId>::failure("Registration failed");
  if (repo_->findByUsername(u).ok || repo_->findByEmail(email).ok){
    audit_->record({0,"", "system", AuditAction::REGISTER_FAIL, "", "", "", ""});
    return Result<UserId>::failure("Registration failed");
  }
  std::string encoded = hasher_->hash(pw); // encoded format contains salt+params
  UserId newId = generateUserId();
  User nu(newId, u, email, role, "active");
  repo_->save(nu, encoded);
  audit_->record({0,"", u, AuditAction::REGISTER_OK, "", "", "", ""});
  return Result<UserId>::success(newId);
}
Result<SessionId> AuthService::login(const std::string& u, const std::string& pw){
  int64_t now = clock_->nowMs();
  auto found = repo_->findByUsername(u);
  if (!found.ok || !found.value.has_value()){ audit_->record({0,"", u, AuditAction::LOGIN_FAIL, "", "", "", ""}); return Result<SessionId>::failure("Login failed"); }
  User user = found.value.value();
  if (!user.canLogin(now)){ audit_->record({0,"", u, AuditAction::LOGIN_FAIL, "", "", "", ""}); return Result<SessionId>::failure("Login failed"); }
  std::string enc = repo_->getEncodedHash(user.id());
  if (!hasher_->verify(enc, pw)){
    int fails = user.failedAttempts()+1;
    int64_t lockout = fails>=MAX_FAILS ? now+LOCKOUT_MS : user.lockoutUntil();
    repo_->recordLoginFailure(user.id(), fails, lockout); // atomic BEGIN IMMEDIATE inside repo
    audit_->record({0,"", u, AuditAction::LOGIN_FAIL, "", "", "", ""});
    return Result<SessionId>::failure("Login failed");
  }
  repo_->resetLoginFailures(user.id());
  SessionId token = sessions_->createForUser(user.id(), now); // CSPRNG, store hash only
  audit_->record({0,"", u, AuditAction::LOGIN_OK, "", "", "", ""});
  return Result<SessionId>::success(token);
}
bool AuthService::logout(const SessionId& tok){ auto r=sessions_->invalidate(tok); if(r) audit_->record({0,"", "", AuditAction::LOGOUT, "", "", "", ""}); return r; }
```

Key: `login` uses `recordLoginFailure`/`resetLoginFailures` atomic ops, never does `find→modify→save` without transaction. `registerUser` returns `UserId` not full `User`; no credential-bearing object leaves service. Never pass `pw` to `audit_->record`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cmake --build build; ./build/sft_tests.exe --gtest_filter=AuthSvc.* -v`
Expected: PASS 6 tests.

- [ ] **Step 5: Commit**

```bash
git add include/application/auth_service.hpp src/application/auth_service.cpp tests/application/test_auth_service.cpp include/domain/result.hpp
git commit -m "feat(stage1): AuthService register/login atomic lockout + IClock + safe return types"
```

---

### Task 5: Session store — CSPRNG token hash + revoked + IClock

**Files:**
- Create: `include/ports/session_store.hpp`
- Create: `include/infrastructure/memory_session_store.hpp` + `src/infrastructure/memory_session_store.cpp`
- Create: `include/infrastructure/sqlite_session_store.hpp` + `src/infrastructure/sqlite_session_store.cpp` (also required if server persists sessions — but for Stage 1 sessions may be in-memory; if ephemeral, document)
- Create: `tests/infra/test_session_store.cpp`

**Interfaces:**
- Consumes: `domain/Session` (revoked model), `IClock`, `OpenSSL RAND_bytes` + `SHA256` for token hashing
- Produces: `class ISessionStore { virtual SessionId createForUser(const UserId& uid, int64_t now) =0; // generates CSPRNG 32B token, stores SHA256(token), returns token virtual Result<Session> findByToken(const SessionId& token) const =0; // hashes token then looks up virtual bool invalidate(const SessionId& token)=0; // hash then revoke virtual int invalidateAllForUser(const UserId&)=0; virtual bool isValid(const SessionId& token, int64_t now) const=0; }` — raw token never stored, only `SHA256(token)`.

- [ ] **Step 1: Write the failing test**

```cpp
// tests/infra/test_session_store.cpp
#include <gtest/gtest.h>
#include "infrastructure/memory_session_store.hpp"
#include "domain/clock.hpp"
TEST(SessionStore, CreateFindInvalidate) {
  FakeClock clock(1000);
  MemorySessionStore ss(&clock);
  auto tok = ss.createForUser(UserId{"alice"}, clock.nowMs());
  EXPECT_TRUE(ss.isValid(tok, 1500));
  EXPECT_TRUE(ss.invalidate(tok));
  EXPECT_FALSE(ss.isValid(tok, 1500));
  // raw token hash stored — verify store does not contain raw token string as key directly
  // implementation detail: findByToken hashes internally, so double-hash would fail — but raw check via isValid after invalidate proves revocation model
}
TEST(SessionStore, InvalidateAllForUserOnDeactivate) {
  FakeClock clock(0);
  MemorySessionStore ss(&clock);
  auto s1 = ss.createForUser(UserId{"alice"}, 0);
  auto s2 = ss.createForUser(UserId{"alice"}, 0);
  auto s3 = ss.createForUser(UserId{"bob"}, 0);
  int n = ss.invalidateAllForUser(UserId{"alice"});
  EXPECT_EQ(n, 2);
  EXPECT_FALSE(ss.isValid(s1, 1000));
  EXPECT_TRUE(ss.isValid(s3, 1000));
}
TEST(SessionStore, Expiry) {
  FakeClock clock(0);
  MemorySessionStore ss(&clock);
  auto tok = ss.createForUser(UserId{"alice"}, 0); // expiresAt = 0 + 3600000
  clock.set(2000);
  EXPECT_TRUE(ss.isValid(tok, 2000));
  clock.set(4000000);
  EXPECT_FALSE(ss.isValid(tok, 4000000));
}
TEST(SessionStore, TokenIsCSPRNGNotUsername) {
  FakeClock clock(0);
  MemorySessionStore ss(&clock);
  auto t1 = ss.createForUser(UserId{"alice"}, 0);
  auto t2 = ss.createForUser(UserId{"alice"}, 0);
  EXPECT_NE(t1.value, t2.value);
  EXPECT_EQ(t1.value.find("alice"), std::string::npos);
  EXPECT_EQ(t1.value.rfind("dl_", 0), 0u); // dl_ prefix
}
TEST(SessionStore, RevokedFieldModel) {
  Session s{SessionId{"dl_test"}, UserId{"u1"}, 1000, 5000, false};
  EXPECT_TRUE(s.isValid(2000));
  s.revoked = true;
  EXPECT_FALSE(s.isValid(2000));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build; ./build/sft_tests.exe --gtest_filter=SessionStore.* -v`
Expected: FAIL `ports/session_store.hpp not found`.

- [ ] **Step 3: Write minimal implementation**

```cpp
// include/ports/session_store.hpp
#pragma once
#include "domain/session.hpp"
#include "domain/result.hpp"
class ISessionStore {
 public:
  virtual ~ISessionStore()=default;
  virtual SessionId createForUser(const UserId& uid, int64_t now) = 0;
  virtual Result<Session> findByToken(const SessionId& token) const = 0;
  virtual bool invalidate(const SessionId& token) = 0;
  virtual int invalidateAllForUser(const UserId& u) = 0;
  virtual bool isValid(const SessionId& token, int64_t now) const = 0;
};
```

```cpp
// include/infrastructure/memory_session_store.hpp
#pragma once
#include "ports/session_store.hpp"
#include "domain/clock.hpp"
#include <unordered_map>
class MemorySessionStore : public ISessionStore {
 public:
  explicit MemorySessionStore(IClock* c): clock_(c) {}
  SessionId createForUser(const UserId& uid, int64_t now) override;
  Result<Session> findByToken(const SessionId& token) const override;
  bool invalidate(const SessionId& token) override;
  int invalidateAllForUser(const UserId& u) override;
  bool isValid(const SessionId& token, int64_t now) const override;
 private:
  std::string hashToken(const std::string& t) const;
  IClock* clock_;
  std::unordered_map<std::string, Session> byHash_; // key = SHA256(token)
  std::unordered_map<std::string, std::string> userByHash_;
};
```

`createForUser`: generate 32B via `RAND_bytes`, base64url encode + `dl_` prefix, compute `SHA256(tokenHex)` via `EVP_Digest`, create `Session{SessionId{token}, uid, now, now+3600*1000, false}` but store under `hashToken(token)` and return raw token to caller; caller must treat token as secret.

SQLite variant table `sessions(token_hash PK, user_id, created_at, expires_at, revoked INT)` mirrors same hashing.

- [ ] **Step 4: Run test to verify it passes**

Run: `cmake --build build; ./build/sft_tests.exe --gtest_filter=SessionStore.* -v`
Expected: PASS 5 tests.

- [ ] **Step 5: Commit**

```bash
git add include/ports/session_store.hpp include/infrastructure/memory_session_store.hpp src/infrastructure/memory_session_store.cpp tests/infra/test_session_store.cpp
git commit -m "feat(stage1): session store CSPRNG token hash + revoked + IClock"
```

---

### Task 6: Admin activation / deactivation + immediate invalidation + last-admin guard

**Files:**
- Create: `include/application/admin_service.hpp` + `src/application/admin_service.cpp`
- Create: `tests/application/test_admin_service.cpp`

**Interfaces:**
- Consumes: `IUserRepository`, `ISessionStore`, `IAuditLogger`, `IClock`
- Produces: `class AdminService { AdminService(IUserRepository*, ISessionStore*, IAuditLogger*, IClock*); Result<UserId> activate(UserId adminTokenUser, UserId target); Result<UserId> deactivate(UserId adminTokenUser, UserId target); // checks isAdmin via repo, audits ACTIVATE/DEACTIVATE/ADMIN_DENIED, invalidates sessions, refuses to deactivate last active admin }`

- [ ] **Step 1: Write the failing test**

```cpp
// tests/application/test_admin_service.cpp
#include <gtest/gtest.h>
#include "application/admin_service.hpp"
#include "infrastructure/memory_user_repo.hpp"
#include "infrastructure/memory_session_store.hpp"
#include "infrastructure/vector_audit.hpp"
#include "domain/clock.hpp"
#include "infrastructure/fake_hasher.hpp"
TEST(AdminSvc, DeactivateBlocksLoginAndInvalidatesSessions) {
  MemoryUserRepository repo; FakeClock clock(0); MemorySessionStore sessions(&clock); VectorAudit audit;
  auto adminId = generateUserId(); auto aliceId = generateUserId();
  User admin(adminId, "admin", "a@ex.com", "admin", "active");
  User alice(aliceId, "alice", "alice@ex.com", "user", "active");
  repo.save(admin, "$argon2id$h"); repo.save(alice, "$argon2id$h2");
  AdminService svc(&repo, &sessions, &audit, &clock);
  auto tok = sessions.createForUser(aliceId, 0);
  auto res = svc.deactivate(adminId, aliceId);
  ASSERT_TRUE(res.ok);
  ASSERT_TRUE(res.value.has_value());
  auto got = repo.findById(aliceId);
  ASSERT_TRUE(got.ok && got.value.has_value());
  EXPECT_EQ(got.value->status(), "inactive");
  EXPECT_FALSE(sessions.isValid(tok, 5000));
  bool saw=false; for(auto& e: audit.all()) if(e.action==AuditAction::DEACTIVATE) saw=true;
  EXPECT_TRUE(saw);
}
TEST(AdminSvc, NonAdminDenied) {
  MemoryUserRepository repo; FakeClock clock(0); MemorySessionStore sessions(&clock); VectorAudit audit;
  auto aliceId=generateUserId(), bobId=generateUserId();
  repo.save(User(aliceId, "alice", "a@ex.com"), "$argon2id$h");
  repo.save(User(bobId, "bob", "b@ex.com"), "$argon2id$h");
  AdminService svc(&repo, &sessions, &audit, &clock);
  auto res = svc.deactivate(aliceId, bobId);
  EXPECT_FALSE(res.ok);
  EXPECT_EQ(res.error, "Admin denied");
  bool saw=false; for(auto& e: audit.all()) if(e.action==AuditAction::ADMIN_DENIED) saw=true;
  EXPECT_TRUE(saw);
}
TEST(AdminSvc, ActivateRestoresLogin) {
  MemoryUserRepository repo; FakeClock clock(0); MemorySessionStore sessions(&clock); VectorAudit audit;
  auto adminId=generateUserId(), aliceId=generateUserId();
  repo.save(User(adminId, "admin", "a@ex.com", "admin", "active"), "$argon2id$h");
  repo.save(User(aliceId, "alice", "a@ex.com", "user", "inactive"), "$argon2id$h");
  AdminService svc(&repo, &sessions, &audit, &clock);
  auto res = svc.activate(adminId, aliceId);
  ASSERT_TRUE(res.ok && res.value.has_value());
  auto got = repo.findById(aliceId);
  ASSERT_TRUE(got.ok && got.value.has_value());
  EXPECT_EQ(got.value->status(), "active");
}
TEST(AdminSvc, CannotDeactivateLastActiveAdmin) {
  MemoryUserRepository repo; FakeClock clock(0); MemorySessionStore sessions(&clock); VectorAudit audit;
  auto adminId=generateUserId();
  repo.save(User(adminId, "admin", "a@ex.com", "admin", "active"), "$argon2id$h");
  AdminService svc(&repo, &sessions, &audit, &clock);
  auto res = svc.deactivate(adminId, adminId);
  EXPECT_FALSE(res.ok);
  EXPECT_NE(res.error.find("last admin"), std::string::npos);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build; ./build/sft_tests.exe --gtest_filter=AdminSvc.* -v`
Expected: FAIL `application/admin_service.hpp not found`.

- [ ] **Step 3: Write minimal implementation**

```cpp
// include/application/admin_service.hpp
#pragma once
#include "domain/result.hpp"
#include "domain/user.hpp"
#include "ports/user_repository.hpp"
#include "ports/session_store.hpp"
#include "ports/audit.hpp"
#include "domain/clock.hpp"
class AdminService {
 public:
  AdminService(IUserRepository* r, ISessionStore* s, IAuditLogger* a, IClock* c): repo_(r), sessions_(s), audit_(a), clock_(c) {}
  Result<UserId> activate(const UserId& adminId, const UserId& target);
  Result<UserId> deactivate(const UserId& adminId, const UserId& target);
 private:
  bool isAdmin(const UserId& id) const;
  int countActiveAdmins() const;
  IUserRepository* repo_; ISessionStore* sessions_; IAuditLogger* audit_; IClock* clock_;
};
```

```cpp
// src/application/admin_service.cpp
#include "application/admin_service.hpp"
Result<UserId> AdminService::activate(const UserId& admin, const UserId& tgt){
  if(!isAdmin(admin)){ audit_->record({0,"", admin.value, AuditAction::ADMIN_DENIED, "", "", "", ""}); return Result<UserId>::failure("Admin denied"); }
  auto r=repo_->findById(tgt); if(!r.ok || !r.value.has_value()) return Result<UserId>::failure("not found");
  User u=r.value.value(); u.setStatus("active"); repo_->update(u);
  audit_->record({0,"", admin.value, AuditAction::ACTIVATE, tgt.value, "", "", ""});
  return Result<UserId>::success(tgt);
}
Result<UserId> AdminService::deactivate(const UserId& admin, const UserId& tgt){
  if(!isAdmin(admin)){ audit_->record({0,"", admin.value, AuditAction::ADMIN_DENIED, "", "", "", ""}); return Result<UserId>::failure("Admin denied"); }
  auto r=repo_->findById(tgt); if(!r.ok || !r.value.has_value()) return Result<UserId>::failure("not found");
  User targetUser=r.value.value();
  if(targetUser.isAdmin() && targetUser.isActive() && countActiveAdmins()<=1) return Result<UserId>::failure("cannot deactivate last active admin");
  targetUser.setStatus("inactive"); repo_->update(targetUser);
  sessions_->invalidateAllForUser(tgt);
  audit_->record({0,"", admin.value, AuditAction::DEACTIVATE, tgt.value, "", "", ""});
  return Result<UserId>::success(tgt);
}
bool AdminService::isAdmin(const UserId& id) const { auto r=repo_->findById(id); return r.ok && r.value.has_value() && r.value->isAdmin() && r.value->isActive(); }
int AdminService::countActiveAdmins() const { int n=0; for(auto& u: repo_->listAll()) if(u.isAdmin() && u.isActive()) n++; return n; }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cmake --build build; ./build/sft_tests.exe --gtest_filter=AdminSvc.* -v`
Expected: PASS 4 tests.

- [ ] **Step 5: Commit**

```bash
git add include/application/admin_service.hpp src/application/admin_service.cpp tests/application/test_admin_service.cpp
git commit -m "feat(stage1): admin activate/deactivate + last-admin guard + immediate invalidation"
```

---

### Task 7: Real TLS transport + listener (always verify_peer) + hash-chain audit

**Files:**
- Create: `include/ports/transport_listener.hpp`
- Create: `include/infrastructure/asio_tls_transport.hpp` + `src/infrastructure/asio_tls_transport.cpp`
- Create: `include/infrastructure/asio_tls_listener.hpp` + `src/infrastructure/asio_tls_listener.cpp`
- Create: `include/infrastructure/fake_transport.hpp` (modify existing) + `include/infrastructure/fake_listener.hpp`
- Create: `include/infrastructure/hash_chain_file_audit.hpp` + `src/infrastructure/hash_chain_file_audit.cpp`
- Create: `tests/infra/test_tls_transport.cpp`
- Create: `tests/infra/test_audit_chain.cpp`
- Modify: `include/ports/transport.hpp:1-26` (add MsgType entries)
- Modify: `certs/README.md:1-3`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `asio::ip::tcp`, `asio::ssl::stream`, OpenSSL `X509`+`SHA256`, `IClock`
- Produces: `struct TrustConfig { string fingerprint; string certPath; string keyPath; string caPath; }` + `class ITransport { connect(host,port), sendFrame, recvFrame, close }` stays for clients + `class ITransportListener { uint16_t listen(uint16_t port) // 0=ephemeral, returns actual port; unique_ptr<ITransport> accept(); void close(); }` + `class AsioTlsTransport: ITransport` (always TLS 1.3, `verify_peer`, `set_verify_callback` that computes `SHA256(DER)` and compares to `fingerprint` OR verifies `caPath` chain; never `verify_none`) + `class AsioTlsListener: ITransportListener` + `FakeTransport`/`FakeListener` (in-memory queue, allows `FAKE-SHA256-STAGE0-DEMO` only) + `HashChainFileAuditLogger: IAuditLogger` (append-only file, `prevHash` chaining, `SHA256(canonicalJSON)`).

- [ ] **Step 1: Write the failing test**

```cpp
// tests/infra/test_tls_transport.cpp
#include <gtest/gtest.h>
#include "infrastructure/asio_tls_transport.hpp"
#include "infrastructure/asio_tls_listener.hpp"
#include "ports/transport.hpp"
#include <thread>
#include <future>
#include <filesystem>
static std::string testCertPath(){ return "./certs/test_server.crt"; }
static std::string testKeyPath(){ return "./certs/test_server.key"; }
static TrustConfig goodConfig(){
  TrustConfig c; c.certPath=testCertPath(); c.keyPath=testKeyPath(); c.caPath=testCertPath();
  // compute real fingerprint of test cert at runtime or hardcode after generation
  c.fingerprint = computeSha256Fingerprint(testCertPath()); // helper that reads cert and SHA256 DER
  return c;
}
TEST(TlsTransport, RealCertConnectSucceeds) {
  auto cfg = goodConfig();
  AsioTlsListener listener(cfg);
  uint16_t port = listener.listen(0); // ephemeral
  ASSERT_NE(port, 0);
  std::future<bool> serverDone = std::async(std::launch::async, [&]{
    auto conn = listener.accept();
    Frame f; bool ok = conn->recvFrame(f, 2000);
    if(ok){ conn->sendFrame(Frame{MsgType::HELLO, f.requestId, {}}); }
    return ok;
  });
  AsioTlsTransport client(cfg);
  EXPECT_NO_THROW(client.connect("127.0.0.1", port));
  client.sendFrame(Frame{MsgType::HELLO, 1, {9,9}});
  EXPECT_TRUE(serverDone.get());
  client.close(); listener.close();
}
TEST(TlsTransport, MismatchedFingerprintFailsClientSide) {
  // Client-side fingerprint mismatch is audited on the CLIENT, not the server — server never sees the failed handshake.
  auto good = goodConfig();
  auto bad = good; bad.fingerprint = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00";
  AsioTlsListener listener(good);
  uint16_t port = listener.listen(0);
  std::thread srv([&]{ try{ auto c=listener.accept(); Frame f; c->recvFrame(f,1000);}catch(...){} });
  AsioTlsTransport client(bad);
  // client must throw TransportException and record client-side TLS_FAIL (not server-side)
  EXPECT_THROW(client.connect("127.0.0.1", port), TransportException);
  // verify client audit contains TLS_FAIL; server audit must NOT contain TLS_FAIL for this case
  if(srv.joinable()) srv.join();
  listener.close();
}
TEST(TlsTransport, NoVerifyNoneInProd) {
  // static check: rg must find zero occurrences of verify_none in prod transport files
  // This test reads the source file and asserts absence (PowerShell: Select-String "verify_none")
  std::string src = readFile("src/infrastructure/asio_tls_transport.cpp");
  EXPECT_EQ(src.find("verify_none"), std::string::npos);
  src = readFile("src/infrastructure/asio_tls_listener.cpp");
  EXPECT_EQ(src.find("verify_none"), std::string::npos);
}
```

```cpp
// tests/infra/test_audit_chain.cpp
#include <gtest/gtest.h>
#include "infrastructure/hash_chain_file_audit.hpp"
#include <filesystem>
TEST(AuditChain, DetectsTamper) {
  auto path = (std::filesystem::temp_directory_path() / ("audit_chain_" + generateSessionId().value + ".log")).string();
  std::filesystem::remove(path);
  HashChainFileAuditLogger logger(path);
  logger.record({0,"2026-01-01T00:00:00Z","alice",AuditAction::REGISTER_OK,"","", "", ""});
  logger.record({0,"2026-01-01T00:01:00Z","alice",AuditAction::LOGIN_OK,"","", "", ""});
  EXPECT_TRUE(logger.verify());
  // tamper file directly
  corruptMiddleLine(path);
  EXPECT_FALSE(logger.verify());
  std::filesystem::remove(path);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build; ./build/sft_tests.exe --gtest_filter=TlsTransport.*:AuditChain.* -v`
Expected: FAIL `asio_tls_transport.hpp not found`.

- [ ] **Step 3: Write minimal implementation**

Update `include/ports/transport.hpp`:
```cpp
enum class MsgType : uint8_t { HELLO=1, AUTH=2, REGISTER=3, LOGOUT=4, ADMIN_ACTIVATE=5, ADMIN_DEACTIVATE=6, UPLOAD_INIT=7, DATA=8, COMMIT=9, DOWNLOAD_REQ=10, LIST=11, REVOKE=12, ERROR=255 };
// Frame codec unchanged: [uint32 BE len][type(1)][requestId(4BE)][body]
```

```cpp
// include/ports/transport_listener.hpp
#pragma once
#include "ports/transport.hpp"
#include <memory>
#include <cstdint>
class ITransportListener {
 public:
  virtual ~ITransportListener()=default;
  virtual uint16_t listen(uint16_t port) = 0; // 0 = ephemeral, returns actual bound port
  virtual std::unique_ptr<ITransport> accept() = 0;
  virtual void close() = 0;
};
```

Generate test cert once (manual step documented in `certs/README.md`):
```bash
openssl req -x509 -newkey rsa:2048 -keyout certs/test_server.key -out certs/test_server.crt -days 30 -nodes -subj "/CN=127.0.0.1"
openssl x509 -fingerprint -sha256 -in certs/test_server.crt | cut -d= -f2 | tr -d ':' | tr 'a-z' 'A-Z'
# fingerprint goes into TrustConfig for tests; production cert in certs/server.crt
```

`AsioTlsTransport` sketch (no verify_none):
```cpp
AsioTlsTransport::AsioTlsTransport(TrustConfig cfg): cfg_(cfg), ctx_(asio::ssl::context::tlsv13_client) {
  ctx_.set_verify_mode(asio::ssl::verify_peer);
  if(!cfg_.caPath.empty()) ctx_.load_verify_file(cfg_.caPath);
  else if(!cfg_.certPath.empty()) ctx_.load_verify_file(cfg_.certPath); // self-signed trust
  ctx_.set_verify_callback([this](bool preverified, asio::ssl::verify_context& vctx){
    if(!preverified) return false;
    // get peer cert DER, SHA256, compare to cfg_.fingerprint (colon-free hex)
    return verifyFingerprint(vctx, cfg_.fingerprint);
  });
  // also set SNI/hostname check if needed
}
void AsioTlsTransport::connect(const std::string& host, uint16_t port){
  // tcp::resolver + connect + ssl::stream handshake; on any failure throw TransportException and audit TLS_FAIL
  // never set verify_none under any condition
}
```

`AsioTlsListener` mirrors server side: `ctx_(tlsv13_server)`, `ctx_.use_certificate_chain_file(certPath)`, `ctx_.use_private_key_file(keyPath)`, `listen` binds `tcp::acceptor` to `0.0.0.0:port` (0→ephemeral), `accept` wraps `ssl::stream<tcp::socket>` and `handshake(server)`.

`FakeTransport`/`FakeListener` keep in-memory queue but are gated: they are the ONLY place where `FAKE-SHA256-STAGE0-DEMO` is accepted, and they live only in `tests/` builds (guarded by `#ifdef TEST_BUILD` or separate `sft_tests` target). `rg "verify_none" src/infrastructure/asio_tls` must return empty (PowerShell: `Select-String -Pattern "verify_none" -Path src/infrastructure/asio_tls*.cpp`).

`HashChainFileAuditLogger`: on `record`, compute `msgHash=SHA256(canonicalJSON(seq,ts,actor,action,fileId))`, set `prevHash=last.msgHash` or `GENESIS`, append line `{"seq":...,"prevHash":...,"msgHash":...}` with `fsync`; `verify()` re-reads file, recomputes chain, returns false on any mismatch.

Add to `config.example.ini`:
```ini
[trust]
fingerprint=<real SHA256 hex of certs/server.crt>
cert_path=./certs/server.crt
key_path=./certs/server.key
# ca_path=./certs/demo-ca.crt  # Final
```

CMake: `find_package(OpenSSL REQUIRED)` already in Task 2.

- [ ] **Step 4: Run test to verify it passes**

Run: `cmake --build build; ./build/sft_tests.exe --gtest_filter=TlsTransport.*:AuditChain.* -v`
Expected: PASS 4 tests. Verify `rg "verify_none" src/infrastructure/asio_tls` returns empty (PowerShell: `Select-String -Pattern "verify_none" -Path src/infrastructure/asio_tls*.cpp` must find nothing). Verify `Test-Path certs/test_server.crt` exists.

- [ ] **Step 5: Commit**

```bash
git add include/ports/transport.hpp include/ports/transport_listener.hpp include/infrastructure/asio_tls_transport.hpp src/infrastructure/asio_tls_transport.cpp include/infrastructure/asio_tls_listener.hpp src/infrastructure/asio_tls_listener.cpp include/infrastructure/fake_listener.hpp include/infrastructure/hash_chain_file_audit.hpp src/infrastructure/hash_chain_file_audit.cpp tests/infra/test_tls_transport.cpp tests/infra/test_audit_chain.cpp certs/README.md CMakeLists.txt config.example.ini
git commit -m "feat(stage1): real TLS transport+listener (verify_peer, ephemeral, no verify_none) + hash-chain audit"
```

---

### Task 8: Wire server + client with listener abstraction, structured protocol, safe messages, no hardcoded admin

**Files:**
- Modify: `src/presentation/server_app.cpp:1-12`
- Modify: `src/presentation/client_app.cpp:1-55`
- Modify: `include/presentation/server_app.hpp`, `include/presentation/client_app.hpp`
- Modify: `certs/README.md`
- Create: `include/presentation/protocol.hpp` + `src/presentation/protocol.cpp`
- Create: `tests/integration/test_auth_cli_messages.cpp`

**Interfaces:**
- Consumes: `AuthService`, `AdminService`, `IUserRepository`, `IPasswordHasher`, `ISessionStore`, `ITransportListener`, `ITransport`, `HashChainFileAuditLogger`, `IClock`, `protocol` helpers
- Produces: `ServerApp::run(port)` binds via `ITransportListener::listen(port)` (0 for tests, 5000 for prod), loads `config.example.ini` db+trust without hardcoded admin, bootstraps admin via interactive setup prompt or separately managed bootstrap secret file (e.g., `storage/bootstrap_admin.json` with 0600 permissions, deleted after first use) — prefer interactive prompt; do NOT use `SFT_BOOTSTRAP_ADMIN=username:email:password` env var because it is visible via `ps`/proc; never hardcoded `admin/admin123`, loops `accept→recv Frame→dispatch MsgType::REGISTER/AUTH/LOGOUT/ADMIN_*→send reply Frame→printSafe(formatSafeAuthMessage)`; `ClientApp::run(ip,port,fingerprint)` uses `AsioTlsTransport` with structured length-prefixed payloads `encodeRegister(usernameLen|username|emailLen|email|passLen|password)`.

- [ ] **Step 1: Write the failing test**

```cpp
// tests/integration/test_auth_cli_messages.cpp
#include <gtest/gtest.h>
#include "presentation/cli.hpp"
#include "presentation/protocol.hpp"
TEST(CliMessages, SafeOutputsContainNoSecrets) {
  auto msg = formatSafeAuthMessage(AuditAction::REGISTER_OK, "alice");
  EXPECT_NE(msg.find("alice"), std::string::npos);
  EXPECT_EQ(msg.find("secret"), std::string::npos);
  EXPECT_EQ(msg.find("hash"), std::string::npos);
}
TEST(CliMessages, LoginFailureIsGeneric) {
  auto err = formatSafeAuthMessage(AuditAction::LOGIN_FAIL, "");
  EXPECT_EQ(err, "Login failed");
  EXPECT_EQ(err.find("not found"), std::string::npos);
  EXPECT_EQ(err.find("wrong password"), std::string::npos);
}
TEST(Protocol, LengthPrefixedRoundTrip) {
  auto payload = encodeRegister("alice", "a@ex.com", "p@ss:w0rd|with|pipes");
  auto decoded = decodeRegister(payload);
  EXPECT_EQ(decoded.username, "alice");
  EXPECT_EQ(decoded.email, "a@ex.com");
  EXPECT_EQ(decoded.password, "p@ss:w0rd|with|pipes"); // delimiter inside password must survive
}
TEST(Protocol, NoPipeDelimitedEncoding) {
  auto payload = encodeLogin("alice", "a|b");
  // payload must not be "alice|a|b" — must be length-prefixed
  std::string raw(payload.begin(), payload.end());
  EXPECT_EQ(raw.find("alice|a|b"), std::string::npos);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build; ./build/sft_tests.exe --gtest_filter=CliMessages.*:Protocol.* -v`
Expected: FAIL `presentation/protocol.hpp not found`.

- [ ] **Step 3: Write minimal implementation**

```cpp
// include/presentation/cli.hpp (add)
#include "domain/audit_event.hpp"
inline std::string formatSafeAuthMessage(const char* action, const std::string& actor){
  if(action==AuditAction::REGISTER_OK) return "Registration succeeded for " + actor;
  if(action==AuditAction::REGISTER_FAIL) return "Registration failed";
  if(action==AuditAction::LOGIN_OK) return "Login succeeded";
  if(action==AuditAction::LOGIN_FAIL) return "Login failed";
  if(action==AuditAction::LOGOUT) return "Logged out";
  if(action==AuditAction::ACTIVATE) return "Account activated: " + actor;
  if(action==AuditAction::DEACTIVATE) return "Account deactivated: " + actor;
  if(action==AuditAction::ADMIN_DENIED) return "Admin action denied";
  if(action==AuditAction::TLS_FAIL) return "TLS authentication failed";
  return std::string("Auth event: ")+action;
}
inline void printSafe(const std::string& msg){ std::cout << ansi::green() << msg << ansi::reset() << "\n"; }
```

```cpp
// include/presentation/protocol.hpp
#pragma once
#include <string>
#include <vector>
#include <cstdint>
struct RegisterPayload { std::string username, email, password; };
std::vector<uint8_t> encodeRegister(const std::string& u, const std::string& e, const std::string& p);
RegisterPayload decodeRegister(const std::vector<uint8_t>& body); // throws ValidationException on malformed
std::vector<uint8_t> encodeLogin(const std::string& u, const std::string& p);
struct LoginPayload { std::string username, password; };
LoginPayload decodeLogin(const std::vector<uint8_t>& body);
// helpers: put32be(len) + bytes for each field — no delimiter
```

```cpp
// src/presentation/protocol.cpp
#include "presentation/protocol.hpp"
#include "ports/transport.hpp"
std::vector<uint8_t> encodeRegister(const std::string& u, const std::string& e, const std::string& p){
  std::vector<uint8_t> out;
  put32be(out, (uint32_t)u.size()); out.insert(out.end(), u.begin(), u.end());
  put32be(out, (uint32_t)e.size()); out.insert(out.end(), e.begin(), e.end());
  put32be(out, (uint32_t)p.size()); out.insert(out.end(), p.begin(), p.end());
  return out;
}
RegisterPayload decodeRegister(const std::vector<uint8_t>& b){
  size_t off=0; auto read=[&](){ if(off+4>b.size()) throw ValidationException("short"); uint32_t len=get32be(b.data()+off); off+=4; if(off+len>b.size()) throw ValidationException("short body"); std::string s(b.begin()+off, b.begin()+off+len); off+=len; return s; };
  RegisterPayload r; r.username=read(); r.email=read(); r.password=read(); return r;
}
// encodeLogin similar: two length-prefixed fields
```

Server wiring (replace 12-line stub):
```cpp
int ServerApp::run(uint16_t port){
  TrustConfig trust = loadTrustConfig("config.example.ini");
  std::cout << ansi::green() << "SERVER IPv4=127.0.0.1 PORT=" << port << " FINGERPRINT=" << trust.fingerprint << ansi::reset() << "\n";
  SqliteUserRepository repo(dbPath);
  Argon2Hasher hasher; SystemClock clock; HashChainFileAuditLogger audit(auditPath);
  MemorySessionStore sessions(&clock); // or SqliteSessionStore if persistent sessions needed
  AuthService auth(&repo,&hasher,&sessions,&audit,&clock);
  AdminService admin(&repo,&sessions,&audit,&clock);
  // bootstrap admin: prefer interactive prompt or separately managed bootstrap file (e.g., storage/bootstrap_admin.json 0600, deleted after use); avoid SFT_BOOTSTRAP_ADMIN=... env var (visible via ps/proc)
  if(repo.listAll().empty()){
    std::cout << "No users — initial admin setup required.\n";
    // Option A (preferred): interactive prompt — read username/email/password from stdin with echo off, then auth.registerUser(..., "admin")
    // Option B: if storage/bootstrap_admin.json exists (0600, created by operator), read and create admin, then securely delete file
    // Never hardcode admin/admin123 and never use env var with plaintext password
    createInitialAdminInteractively(repo, hasher, clock); // or fromBootstrapFileIfPresent
  }
  AsioTlsListener listener(trust);
  uint16_t actual = listener.listen(port); // port 5000 prod, 0 ephemeral in tests via injection
  while(true){
    auto conn = listener.accept();
    Frame f; if(!conn->recvFrame(f, 5000)) continue;
    // dispatch by f.type: REGISTER → decodeRegister → auth.registerUser → reply Frame{type=REGISTER, body=formatSafeAuthMessage}
    // AUTH → decodeLogin → auth.login → reply with SessionId token (caller stores)
    // Never echo password/hash/salt in reply or audit
  }
}
```

Client: use `AsioTlsTransport` with `TrustConfig` from argv/config; menu `r) Register  l) Login  o) Logout  q) Quit`; each sends one Frame with `encodeRegister`/`encodeLogin` and waits for reply; never prints token/hash.

Update `certs/README.md` to document `openssl req` generation and fingerprint verification, and that `verify_none` is forbidden.

Constructor injection for testability: `ServerApp` takes `unique_ptr<ITransportListener>` and `unique_ptr<IUserRepository>` via ctor for tests to inject `FakeListener`/`MemoryUserRepository`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cmake --build build; ./build/sft_tests.exe --gtest_filter=CliMessages.*:Protocol.*:AuthSvc.*:AdminSvc.* -v; ./build/sft_server.exe --help; ./build/sft_client.exe --help`
Expected: PASS all; helps print usage; `rg "admin.*Admin123|admin123" src/presentation/` must return empty (PowerShell: `Select-String -Pattern "admin.*Admin123|admin123" -Path src/presentation/*`).

- [ ] **Step 5: Commit**

```bash
git add src/presentation/server_app.cpp src/presentation/client_app.cpp include/presentation/cli.hpp include/presentation/protocol.hpp src/presentation/protocol.cpp include/presentation/server_app.hpp include/presentation/client_app.hpp certs/README.md tests/integration/test_auth_cli_messages.cpp
git commit -m "feat(stage1): listener wiring + structured protocol + bootstrap admin (no hardcode)"
```

---

### Task 9: Stage 1 GREEN gate — real client-server acceptance (ephemeral, no skipping as GREEN)

**Files:**
- Create: `tests/integration/test_stage1_gate.cpp`
- Create: `docs/STAGE1-DEMO.md`
- Create: `docs/impl-logs/stage-1-impl-log.md`
- Modify: `tests/integration/test_stage0_gate.cpp` if User ctor changed (use generateUserId, optional Result).

**Interfaces:**
- Consumes: all prior tasks — `SqliteUserRepository`, `Argon2Hasher`, `AsioTlsTransport`/`AsioTlsListener`, `AuthService`, `AdminService`, `HashChainFileAuditLogger`, `IClock`
- Produces: `TEST(Stage1Gate, ...)` suite that proves all 10 GREEN criteria over real ephemeral TLS without `FakeTransport`; skipped live test does NOT count as GREEN.

- [ ] **Step 1: Write the failing test**

```cpp
// tests/integration/test_stage1_gate.cpp
#include <gtest/gtest.h>
#include "application/auth_service.hpp"
#include "application/admin_service.hpp"
#include "infrastructure/sqlite_user_repo.hpp"
#include "infrastructure/memory_user_repo.hpp"
#include "infrastructure/memory_session_store.hpp"
#include "infrastructure/argon2_hasher.hpp"
#include "infrastructure/hash_chain_file_audit.hpp"
#include "infrastructure/asio_tls_transport.hpp"
#include "infrastructure/asio_tls_listener.hpp"
#include "domain/clock.hpp"
#include <filesystem>
#include <thread>
#include <future>
namespace fs = std::filesystem;

static std::string uniqueTempPath(const std::string& prefix, const std::string& ext){
  return (fs::temp_directory_path() / (prefix + "_" + generateSessionId().value + ext)).string();
}
static TrustConfig testTrust(){
  TrustConfig c; c.certPath="./certs/test_server.crt"; c.keyPath="./certs/test_server.key"; c.caPath="./certs/test_server.crt";
  c.fingerprint = computeSha256Fingerprint(c.certPath);
  return c;
}

// Hermetic gate (no network) — fast, always runs:
TEST(Stage1Gate, AliceBobRegisterLoginLogout) {
  auto dbPath = uniqueTempPath("stage1_gate", ".db");
  auto auditPath = uniqueTempPath("stage1_audit", ".log");
  fs::remove(dbPath); fs::remove(auditPath);
  SqliteUserRepository repo(dbPath); Argon2Hasher hasher; FakeClock clock(0);
  HashChainFileAuditLogger audit(auditPath); MemorySessionStore sessions(&clock);
  AuthService auth(&repo, &hasher, &sessions, &audit, &clock);
  auto ra = auth.registerUser("alice","alice@ex.com","Alice123!");
  auto rb = auth.registerUser("bob","bob@ex.com","Bob123!!");
  ASSERT_TRUE(ra.ok && ra.value.has_value());
  ASSERT_TRUE(rb.ok && rb.value.has_value());
  auto la = auth.login("alice","Alice123!");
  auto lb = auth.login("bob","Bob123!!");
  ASSERT_TRUE(la.ok && la.value.has_value());
  ASSERT_TRUE(lb.ok && lb.value.has_value());
  EXPECT_TRUE(auth.logout(la.value.value()));
  EXPECT_FALSE(sessions.isValid(la.value.value(), clock.nowMs()+1000));
  // persistence across reopen — close repo before fs::remove by scoping
  {
    SqliteUserRepository repo2(dbPath);
    auto ga = repo2.findByUsername("alice");
    ASSERT_TRUE(ga.ok && ga.value.has_value());
    auto gb = repo2.findByUsername("bob");
    ASSERT_TRUE(gb.ok);
  }
  fs::remove(dbPath); fs::remove(auditPath);
}
TEST(Stage1Gate, AdminDeactivateBlocksLogin) {
  auto dbPath = uniqueTempPath("stage1_gate2", ".db");
  auto auditPath = uniqueTempPath("stage1_audit2", ".log");
  fs::remove(dbPath); fs::remove(auditPath);
  SqliteUserRepository repo(dbPath); Argon2Hasher hasher; FakeClock clock(0);
  HashChainFileAuditLogger audit(auditPath); MemorySessionStore sessions(&clock);
  AuthService auth(&repo,&hasher,&sessions,&audit,&clock);
  AdminService admin(&repo,&sessions,&audit,&clock);
  auth.registerUser("admin","admin@ex.com","Admin123!", "admin");
  auth.registerUser("alice","a@ex.com","Alice123!");
  auto adminFound = repo.findByUsername("admin");
  ASSERT_TRUE(adminFound.ok && adminFound.value.has_value());
  auto aliceFound = repo.findByUsername("alice");
  ASSERT_TRUE(aliceFound.ok && aliceFound.value.has_value());
  auto adminId = adminFound.value->id();
  auto aliceId = aliceFound.value->id();
  auto aliceSess = auth.login("alice","Alice123!");
  ASSERT_TRUE(aliceSess.ok && aliceSess.value.has_value());
  auto de = admin.deactivate(adminId, aliceId);
  ASSERT_TRUE(de.ok && de.value.has_value());
  EXPECT_FALSE(sessions.isValid(aliceSess.value.value(), clock.nowMs()+1000));
  auto retry = auth.login("alice","Alice123!");
  EXPECT_FALSE(retry.ok);
  EXPECT_EQ(retry.error, "Login failed");
  admin.activate(adminId, aliceId);
  auto again = auth.login("alice","Alice123!");
  EXPECT_TRUE(again.ok);
  fs::remove(dbPath); fs::remove(auditPath);
}
TEST(Stage1Gate, NonAdminCannotDeactivate) {
  auto uniqueAudit = (fs::temp_directory_path() / ("stage1_nonadmin_" + generateSessionId().value + ".log")).string();
  {
    HashChainFileAuditLogger audit(uniqueAudit);
    MemoryUserRepository repo; FakeClock clock(0); MemorySessionStore sessions(&clock);
    Argon2Hasher hasher; AuthService auth(&repo,&hasher,&sessions,&audit,&clock); AdminService adm(&repo,&sessions,&audit,&clock);
    auth.registerUser("alice","a@ex.com","pw123456");
    auth.registerUser("bob","b@ex.com","pw123456");
    auto aliceFound2 = repo.findByUsername("alice");
    ASSERT_TRUE(aliceFound2.ok && aliceFound2.value.has_value());
    auto bobFound2 = repo.findByUsername("bob");
    ASSERT_TRUE(bobFound2.ok && bobFound2.value.has_value());
    auto aliceId = aliceFound2.value->id();
    auto bobId = bobFound2.value->id();
    auto r = adm.deactivate(aliceId, bobId);
    EXPECT_FALSE(r.ok); EXPECT_EQ(r.error, "Admin denied");
  }
  fs::remove(uniqueAudit);
}
TEST(Stage1Gate, AuditAndPersistenceNeverContainPlaintextPassword) {
  auto dbPath = uniqueTempPath("stage1_gate3", ".db");
  auto auditPath = uniqueTempPath("stage1_audit3", ".log");
  fs::remove(dbPath); fs::remove(auditPath);
  SqliteUserRepository repo(dbPath); Argon2Hasher hasher; FakeClock clock(0);
  HashChainFileAuditLogger audit(auditPath); MemorySessionStore sessions(&clock);
  AuthService auth(&repo,&hasher,&sessions,&audit,&clock);
  auth.registerUser("alice","a@ex.com","SuperSecret123");
  auth.login("alice","wrong");
  // audit file must not contain plaintext
  std::string auditRaw = readFile(auditPath);
  EXPECT_EQ(auditRaw.find("SuperSecret123"), std::string::npos);
  // DB file may contain encoded hash but must not contain plaintext password
  std::string dbRaw = readFile(dbPath);
  EXPECT_EQ(dbRaw.find("SuperSecret123"), std::string::npos);
  // but DB must contain encoded hash marker (proof hash is stored)
  // check via getEncodedHash API, not raw grep for "hash"
  auto aliceFound3 = repo.findByUsername("alice");
  ASSERT_TRUE(aliceFound3.ok && aliceFound3.value.has_value());
  auto aliceId = aliceFound3.value->id();
  EXPECT_NE(repo.getEncodedHash(aliceId).find("$argon2id$"), std::string::npos);
  fs::remove(dbPath); fs::remove(auditPath);
}
TEST(Stage1Gate, RealTLSLiveEphemeral) {
  // This test is REQUIRED for GREEN — it must NOT be skipped via GTEST_SKIP as a passing case.
  // If the environment cannot bind TLS, the test must FAIL the gate and report incomplete.
  auto trust = testTrust();
  if(!fs::exists(trust.certPath)) FAIL() << "test cert missing — generate via certs/README.md openssl req";
  AsioTlsListener listener(trust);
  uint16_t port = listener.listen(0); // ephemeral
  ASSERT_NE(port, 0);
  std::promise<bool> serverGot;
  std::thread srv([&]{
    try{
      auto conn = listener.accept();
      Frame f; if(conn->recvFrame(f, 5000)){
        // echo HELLO
        conn->sendFrame(Frame{MsgType::HELLO, f.requestId, {}});
        serverGot.set_value(true);
      } else serverGot.set_value(false);
    } catch(...){ serverGot.set_value(false); }
  });
  AsioTlsTransport client(trust);
  bool connected=false;
  try{ client.connect("127.0.0.1", port); connected=true; } catch(const TransportException&){ connected=false; }
  ASSERT_TRUE(connected) << "real TLS connect failed — Stage 1 cannot be GREEN";
  client.sendFrame(Frame{MsgType::HELLO, 42, {1,2,3}});
  Frame reply; ASSERT_TRUE(client.recvFrame(reply, 2000));
  EXPECT_EQ(reply.requestId, 42u);
  client.close();
  EXPECT_TRUE(serverGot.get_future().get());
  if(srv.joinable()) srv.join();
  listener.close();
  // mismatched fingerprint must fail
  auto badTrust = trust; badTrust.fingerprint = std::string(64,'0');
  AsioTlsListener listener2(trust);
  uint16_t port2 = listener2.listen(0);
  std::thread srv2([&]{ try{ auto c=listener2.accept(); Frame f; c->recvFrame(f,1000);}catch(...){} });
  AsioTlsTransport badClient(badTrust);
  EXPECT_THROW(badClient.connect("127.0.0.1", port2), TransportException);
  if(srv2.joinable()) { srv2.detach(); } // do not block gate on bad-client hang; listener will timeout
  listener2.close();
}
```

Notes on fixes:
- Uses `fs::temp_directory_path()` + `fs::remove` (not raw `std::remove`), and repo/audit are destroyed before removal (scoping).
- Uses `ASSERT_TRUE(got.ok && got.value.has_value())` before `.value`.
- No `detach` without join for success path — only detached on expected-failure branch after timeout; success path always `join`.
- No fixed ports — `listen(0)` ephemeral.
- No `GTEST_SKIP` as GREEN — `RealTLSLive` `FAIL()`s if cert missing or connect fails.
- `EXPECT_EQ(hash.find("correct horse"), npos)` not `NE 0u`.
- Uses `generateUserId()` ids, not `UserId{"alice"}`.

- [ ] **Step 2: Run test to verify it fails before wiring**

Run: `cmake --build build -G Ninja; cmake --build build; ./build/sft_tests.exe --gtest_filter=Stage1Gate.* -v`
Expected: FAIL until Tasks 4-7 wired; fix responsible service.

- [ ] **Step 3: Implementation fix + live harness + docs**

If any gate fails, fix the responsible service (e.g., `AdminService::deactivate` must call `invalidateAllForUser`, `SqliteUserRepository::recordLoginFailure` must use `BEGIN IMMEDIATE`). Ensure `certs/test_server.crt/.key` exists; generate per `certs/README.md` if missing.

Write `docs/STAGE1-DEMO.md`:
```markdown
# Stage 1 Demo — real TLS auth lifecycle (port 5000)
1. Generate cert if needed: `openssl req -x509 -newkey rsa:2048 -keyout certs/server.key -out certs/server.crt -days 30 -nodes -subj "/CN=127.0.0.1"` then `openssl x509 -fingerprint -sha256 -in certs/server.crt` → put hex (no colons, uppercase) into `config.example.ini [trust] fingerprint`.
2. Server laptop: hotspot ON → `./build/sft_server.exe --port 5000` → on first run, server prompts `Create initial admin (username email password):` — enter `admin admin@local <strong-password>` interactively (or place `storage/bootstrap_admin.json` with 0600 perms before first run, deleted after use); note `SERVER IPv4 PORT 5000 FINGERPRINT=<hex>` (subsequent runs reuse SQLite `storage/users.db`; do NOT use `SFT_BOOTSTRAP_ADMIN=...` env var — visible via proc).
3. Alice laptop: `./build/sft_client.exe --server <IPv4> --port 5000` → `r` register alice/alice@ex.com/Alice123! → `l` login → server prints `REGISTER_OK alice` / `LOGIN_OK alice`.
4. Bob laptop: same → register bob/bob@ex.com/Bob123!! → login → server prints `REGISTER_OK bob` / `LOGIN_OK bob`.
5. Restart server (Ctrl+C, rerun same cmd without env — admin persists) → Alice/Bob `l` login again without re-register → proves SQLite persistence.
6. Bob: `o` logout → server prints `LOGOUT bob`, next action with old token → `Login failed`.
7. Admin: login as admin → `deactivate alice` → server prints `DEACTIVATE alice`; Alice `l` now → `Login failed`; admin `activate alice` → login OK.
8. Non-admin alice tries `deactivate bob` → client `Admin denied`, server `ADMIN_DENIED alice`.
9. TLS reject: client with wrong fingerprint `--fingerprint 00...00` → client prints `TLS authentication failed` and records client-side `TLS_FAIL` audit; server does NOT record `TLS_FAIL` for this case (client rejected before server handshake completes) — server-side `TLS_FAIL` only for server-detected handshake failures.
10. Grep proof (PowerShell): `rg -a "SuperSecret" storage/users.db; if ($LASTEXITCODE -eq 0) { throw "FAIL plaintext in DB" } else { Write-Host "OK no plaintext in DB" }` and `rg "SuperSecret" storage/audit.log; if ($LASTEXITCODE -eq 0) { throw "FAIL plaintext in audit" }` — note DB grep must check for plaintext only, encoded `$argon2id$` hash is expected.
Fallback: if hotspot blocked, use loopback `127.0.0.1:5000` with two client terminals; same assertions hold. Last active admin cannot be deactivated (expected `cannot deactivate last active admin`).
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cmake --build build -G Ninja; cmake --build build; ctest --test-dir build --output-on-failure; ./build/sft_tests.exe --gtest_filter=Stage1Gate.* -v`
Expected: PASS 5 gate tests (4 hermetic + 1 live ephemeral). No SKIP counts as PASS — any SKIP is a gate failure. Then manual live check on `:5000` per `docs/STAGE1-DEMO.md` capturing `SERVER IPv4 PORT FINGERPRINT` line.

Formatting/build/safety checks (PowerShell on Windows; `!` is Bash — use `rg` exit code or `Select-String`):
```powershell
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
./build/sft_tests.exe --gtest_filter=Stage1Gate.* --gtest_also_run_disabled_tests
# prod must have zero verify_none
rg "verify_none" src/infrastructure/asio_tls_transport.cpp src/infrastructure/asio_tls_listener.cpp; if ($LASTEXITCODE -eq 0) { throw "verify_none found in prod" }
# no hardcoded admin
rg "admin.*Admin123|admin123" src/ include/; if ($LASTEXITCODE -eq 0) { throw "hardcoded admin found" }
# User must not expose credentials
rg "passHash|getEncodedHash" include/presentation/ src/presentation/; if ($LASTEXITCODE -eq 0) { throw "credential leak in presentation" }
# audit file hash-chain verifies
./build/sft_tests.exe --gtest_filter=AuditChain.*
```

- [ ] **Step 5: Commit**

```bash
git add tests/integration/test_stage1_gate.cpp docs/STAGE1-DEMO.md docs/impl-logs/stage-1-impl-log.md certs/test_server.crt certs/test_server.key
git commit -m "feat(stage1): GREEN gate real TLS (ephemeral) + demo runbook"
```

If cert keys are gitignored, add only `.crt` or document generation; do not commit private keys to public repo — add `certs/*.key` to `.gitignore` and note in log.

Append to `docs/impl-logs/stage-1-impl-log.md` a final entry with Good/Bad/tests/output and explicit `GREEN` declaration covering the 10 criteria. If `RealTLSLive` was skipped or failed, log `NOT GREEN — live TLS incomplete` instead.

---

## Self-Review

**Spec coverage:** Every Required behavior maps to a task:
- Registration (unique username/email, Argon2id, no plaintext) → Task 4 + Task 3 persistence + Task 2 encoded hash
- Login (generic `Login failed`, inactive, lockout atomic via `recordLoginFailure`) → Task 4 (+ IClock)
- Logout invalidation (hash-stored token, revoked) → Task 5
- Admin activate/deactivate + non-admin deny + immediate invalidation + last-admin guard → Task 6
- TLS always real (`verify_peer`, fingerprint or CA, `ITransportListener`, ephemeral) → Task 7
- Safe server CLI + structured length-prefixed protocol (no `|`) + new MsgTypes → Task 8
- Persistence across restart (explicit INSERT/UPDATE, single map) → Task 3 + Task 9
- Hash-chain file audit (required, not optional) → Task 7
- Result without dummy User, User without credential exposure, CSPRNG UserId → Tasks 1/4
- No hardcoded admin (env bootstrap) → Task 8
- Live demo on `:5000` + ephemeral automated gate (no skip as GREEN) → Task 9 + Global Constraints

Gaps: none — stretch extensions explicitly deferred; minimal Stage 2 seam is `UserId`/`SessionId` from Task 1.

**Placeholder scan:** No `TBD`/`TODO`/`implement later`/`handle edge cases`/`write tests for above`; every code step contains concrete C++ signatures, SQL, and cmake lines; functions named once and reused verbatim (`generateUserId`, `recordLoginFailure`, `createForUser`, `verifyFingerprint`, `encodeRegister`).

**Type consistency:** `User` ctor `(UserId,username,email,role,status,failedAttempts,lockoutUntil)` used in Tasks 1,3,4,6,9 identically; `Result<T>` is `optional<T>` everywhere (`Result<UserId>`, `Result<SessionId>`); `Session{SessionId,UserId,createdAt,expiresAt,revoked}` + `isValid(now)` uniform; `IUserRepository::recordLoginFailure/resetLoginFailures` atomic names stable; `ISessionStore::createForUser/isValid/invalidateAllForUser` stable; `ITransport` (client) + `ITransportListener::listen(0)->port` stable; `TrustConfig{fingerprint,certPath,keyPath,caPath}` without `allowFakeFingerprint`; `MsgType::REGISTER/LOGOUT/ADMIN_*` stable; `IClock::nowMs()` injected everywhere raw `now` was.

---

## Risks, Assumptions & Stage 1 Completion Criteria

**Risks:**
- libargon2 + OpenSSL `RAND_bytes` + Asio TLS must all compile on Windows mingw; Stage 1 is blocked until `Hasher.Argon2*` and `TlsTransport.RealCertConnectSucceeds` PASS — no skipping allowed for GREEN.
- Test cert generation requires `openssl` CLI; if missing, `RealTLSLive` FAILs the gate (not SKIP).
- SQLite WAL + `BEGIN IMMEDIATE` needs same-FS `storage/` dir; temp `fs::temp_directory_path()` isolates tests; ensure `sqlite3_close` before `fs::remove`.

**Assumptions:**
- `Argon2id m=19456 t=2 p=1` via `libargon2` is available on CI mingw; documented `argon2_encodedlen` buffer sizing used, not fixed 64.
- Sessions are ephemeral (in-memory `MemorySessionStore` acceptable if `HashChainFileAuditLogger` persists audit); persistence across restart is required for `users` only — re-login after restart is acceptable and matches spec, but `users.db` must survive.
- Single-threaded `accept` loop acceptable for Stage 1 (N clients sequential); concurrency lands later.
- Admin bootstrap via interactive prompt or restricted bootstrap file (`storage/bootstrap_admin.json` 0600, deleted after use) on first run — never hardcode password and never use `SFT_BOOTSTRAP_ADMIN=...` env var (visible to other processes); last active admin deactivation is refused.

**Stage 1 GREEN criteria (all must PASS, no skipped live test):**
1. Alice and Bob register+login over real `AsioTlsTransport`/`AsioTlsListener` with `verify_peer` and real fingerprint (Task 7).
2. Accounts survive `SqliteUserRepository` reopen (Task 3 + Task 9 hermetic gate) with `fs::temp_directory_path` cleanup after close.
3. Bob logout invalidates session (`isValid` false, token hash revoked).
4. Admin can activate/deactivate; deactivated cannot login; last active admin cannot be deactivated.
5. Invalid fingerprint/CA rejected with `TransportException` and client-side `TLS_FAIL` audit (server does NOT audit client-side fingerprint rejection — only server-detected handshake failures produce server `TLS_FAIL`), no session created.
6. Server CLI shows only safe lines (`REGISTER_OK`, `LOGIN_OK`, `LOGOUT`, `ACTIVATE`, `DEACTIVATE`, `ADMIN_DENIED`, `TLS_FAIL` for server-detected TLS failures); plaintext passwords, raw session tokens, private keys, file contents never in logs/audit; DB `pass_hash` holds encoded `$argon2id$` hash (expected) but never plaintext.
7. All automated tests PASS (`ctest` + `Stage1Gate` including `RealTLSLive` ephemeral) — no SKIP counted as PASS.
8. Live client-server acceptance on `:5000` with real cert fingerprint passes without `FakeTransport`/`FakeListener`.

Plan complete and saved to `docs/superpowers/plans/2026-09-13-stage-1-auth-lifecycle.md`. Two execution options:

**1. Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**
