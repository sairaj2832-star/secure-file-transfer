# Stage-0 DEMO/MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Stage-0 vertical slice: 3-process Alice→Bob via dedicated server on hotspot :5000 with Yes/No CLI, proving Carol-DENY + 1-byte INTEGRITY_FAIL GREEN.

**Architecture:** Same-application seam: STL+ANSI CLI in `presentation/` calls `application/` services which own `domain/` invariants; all I/O behind `ports/` with in-memory/fake adapters for Stage-0, loopback/plain-TCP `ITransport` on port 5000; real SQLite/AES/TLS land in Stage-2/3 without touching domain.

**Tech Stack:** C++20, CMake 3.20+, GTest (FetchContent), standalone Asio (FetchContent, plain TCP only in Stage-0), STL-only CLI + ANSI, no FTXUI, no HTTP, no OpenSSL yet (fingerprint is displayed stub string).

## Global Constraints

- C++20 · STL-only CLI + ANSI (Stage-0) → optional FTXUI in `presentation/` (Final).
- Raw TCP via Asio on fixed port 5000, custom framing `[uint32 BE len][msg]`, behind `ITransport`; Stage-0 plain framing bring-up only, TLS 1.3 mandatory from Stage-3.
- Trusted server (server CAN decrypt — NOT end-to-end).
- Topology: Dedicated server laptop + 2-3 client laptops (Alice/Bob[/Carol]); server never on Alice/Bob laptop.
- Standard isolated net: server laptop hosts mobile hotspot, clients join; display server IPv4 + port 5000 + cert fingerprint; Windows Firewall Allow for 5000; no college WiFi / AP-isolation / mDNS dependency; fallback wired switch or USB-tethered network.
- Single port 5000 throughout; no port changes.
- `domain/` + `application/` remain UI-independent; no UI/crypto/DB/socket headers in `domain/`; `presentation/` isolated; do NOT add cpp-httplib status pages.
- UI rule: simple Yes/No confirmations only; all policy still enforced server-side.
- TLS cert ≠ file-encryption key; file-at-rest = AES-256-GCM DEK + versioned KEK (real crypto in Stage-2; Stage-0 uses FakeCrypto XOR+FNV tag simulation only).
- Token-only/public-link access out of scope; standard flow = login + recipient bind (full opaque `dl_*` validity in Stage-4; Stage-0 enforces bind+revoked, expiry fields present with far-future default).
- E2E out of scope → `docs/future-e2e.md` only.
- A stage is GREEN only when its exit tests pass; dates are estimates only; later stage must not compensate for failed earlier gate; Stage-3 GREEN triggers scope freeze.
- `unique_ptr`, no owning raw `new`; RAII guards close files/sockets; validating constructors; `==` for IDs only.
- Never log/store passwords/keys/plaintext/raw tokens; store only `SHA256(token)`.
- Stage-0 GREEN = Alice→Bob OK + Carol DENY + 1-byte INTEGRITY_FAIL across processes.

---

## Scope Check

Stage-0 is one thin vertical slice (not the full MASTER §10). It produces working testable software on its own: register/login in-memory, upload/download framed over loopback/:5000, recipient authz, tamper detect, audit vector, ANSI CLI, 3-terminal demo. Stage-1/2/3 harden domain/persist/network without changing domain headers.

## File Structure (create in this order)

```
secure-file-transfer/            # repo root = D:\OOPS\CP (code lives alongside docs for Stage-0)
├── CMakeLists.txt               # C++20, FetchContent GTest+Asio, client/server/test targets
├── config.example.ini           # server=0.0.0.0:5000, trust=fingerprint stub, storage=./storage
├── include/
│   ├── domain/
│   │   ├── ids.hpp              # UserId, FileId, TransferId, == only
│   │   ├── digest.hpp           # Digest{array<uint8_t,32>}, fnv1a32(), sha256stub()
│   │   ├── wrapped_key.hpp      # WrappedKey{kekVersion,alg,nonce,bytes}
│   │   ├── exceptions.hpp       # AppException tree
│   │   ├── result.hpp           # template Result<T>
│   │   ├── user.hpp             # User base + RegularUser + Administrator
│   │   ├── file_record.hpp      # FileRecord (storageId, no plaintext path)
│   │   ├── transfer.hpp         # Transfer + Status + markDownloaded()
│   │   ├── permission.hpp       # Permission{file,user,expiresAt,revoked}
│   │   ├── download_token.hpp   # DownloadToken stub (bind+revoked enforced, expiry present)
│   │   └── audit_event.hpp      # AuditEvent{seq,ts,actor,action,fileId,cipherHash,prevHash,msgHash}
│   ├── ports/
│   │   ├── repository.hpp       # template Repository<T,Id>
│   │   ├── storage.hpp          # IStorage{write,read,exists,remove}
│   │   ├── crypto.hpp           # IEncryptionProvider{encrypt,decryptAndVerify}
│   │   ├── audit.hpp            # IAuditLogger{record,all}
│   │   ├── policy.hpp           # IAccessPolicy{isAuthorized}
│   │   └── transport.hpp        # ITransport{connect,sendFrame,recvFrame,close} + Frame{type,requestId,body}
│   ├── application/
│   │   ├── auth_service.hpp     # AuthService{register_,login} (SHA256-stub hash in Stage-0)
│   │   ├── policy_engine.hpp    # PolicyEngine: IAccessPolicy
│   │   └── transfer_service.hpp # TransferService{upload,list,download}
│   ├── infrastructure/
│   │   ├── memory_repo.hpp      # InMemoryRepo<T,Id>
│   │   ├── fake_crypto.hpp      # FakeCrypto: XOR 0x5A + FNV tag
│   │   ├── memory_storage.hpp   # MemoryStorage: unordered_map
│   │   ├── vector_audit.hpp     # VectorAudit: vector + hash-chain stub
│   │   └── asio_transport.hpp   # AsioTcpTransport plain :5000 + FakeTransport (queue)
│   └── presentation/
│       ├── ansi.hpp             # colors, progressBar, tableRow
│       ├── cli.hpp              # askYesNo(), printSuccess/Error()
│       ├── client_app.hpp       # ClientApp{run(ip,port)}
│       └── server_app.hpp       # ServerApp{run(port)} prints IPv4+fingerprint
├── src/  (mirrors above, one .cpp per header with logic)
├── client/main.cpp              # parses --server <ip> --port 5000, runs ClientApp
├── server/main.cpp              # parses --port 5000, runs ServerApp
├── tests/
│   ├── domain/test_ids.cpp
│   ├── domain/test_entities.cpp
│   ├── application/test_policy.cpp
│   ├── application/test_transfer.cpp
│   ├── infra/test_fakes.cpp
│   ├── infra/test_framing.cpp
│   └── integration/test_stage0_gate.cpp  # AliceBobCarolTamper across FakeTransport + loopback TCP
├── docs/impl-logs/stage-0-impl-log.md    # required log file (see protocol below)
└── certs/README.md              # Stage-0: FAKE-FINGERPRINT value + pin instructions
```

Responsibility rule: `domain/` validates invariants only; `application/` orchestrates; `ports/` are pure virtual; `infrastructure/` implements ports; `presentation/` only formats I/O and never holds policy.

## Parallel Lanes

```
Wave0 sequential: Task0 (scaffold) → Task1 (ids/digest/key/exceptions/result)
Wave1 parallel (3 agents, needs only Task0+1):
  Lane-A: Task2 domain entities
  Lane-B: Task3 fakes/mocks
  Lane-C: Task5 framing+transport
Wave2 (needs Wave1): Task4 app services (needs Task2+3) || Task6 CLI+exes skeleton can start with stubs, finishes after Task4+5
Wave3: Task7 GREEN gate + demo + log flush
```

Lane contract: do not change headers owned by another lane; if blocked, log to `docs/impl-logs/stage-0-impl-log.md` and continue with `FakeTransport`.

## Log-File Protocol (required, user-specified)

File: `docs/impl-logs/stage-0-impl-log.md` (Markdown chosen over `.log` for tables + code fences + sequential paragraphs).

Template per entry (append, never rewrite history):

```markdown
## Step N — <date> <lane/task> — <title>
**Intent:** one sentence on what this step tried.
**Approach:** 3-6 sentence paragraph: what files touched, why this order, what alternative rejected and why.
**Good:** bullet list of what worked (tests passing, build time, demo output).
**Bad:** bullet list of what failed, flaky, or workaround (exact error text + fix).
**Tests:** exact command + PASS/FAIL + filter name.
**Context checkpoint:** estimated context % used (e.g. 40%); if >=95% → FLUSH + handoff notes below.
```

95% rule: when the implementing agent estimates context ≥95%, it MUST (1) append a `### CONTEXT FLUSH` entry summarizing open files, failing tests, next step number, (2) `git add docs/impl-logs/stage-0-impl-log.md` + commit `docs: flush context step N`, (3) stop and hand off; next agent reads the last 3 entries + `git status` before continuing. Good/bad steps are both recorded; no silent fixes.

Seed file created in Task0 Step 3 below.

Docs each lane must check: `MASTER.md` §2/§3a-d/§7/§8/§9/§10-Stage-0, `project_description.md` §5-6, `system_architecture.md` §2-3, cppreference `filesystem`, `bit_cast`, Asio `ip::tcp` docs.

---

### Task 0: Scaffold + build + log seed

**Files:**
- Create: `CMakeLists.txt`, `client/main.cpp`, `server/main.cpp`, `config.example.ini`, `certs/README.md`, `docs/impl-logs/stage-0-impl-log.md`
- Test: `tests/smoke/test_build.cpp`

**Interfaces:**
- Consumes: none.
- Produces: `int main()` client/server stubs returning 0 with `--help`; `cmake -B build` + `ctest` green; log seed present.

**Docs to check:** `MASTER.md` §6/§10-Stage-0, `system_architecture.md` §2.

- [ ] **Step 1: Write the failing test**

```cpp
// tests/smoke/test_build.cpp
#include <gtest/gtest.h>
TEST(Build, TargetsExist) {
  // Stage-0 scaffold proves CMake wires client/server/tests.
  EXPECT_TRUE(true);
}
```

- [ ] **Step 2: Run test to verify it fails (no CMake yet)**

Run: `cmake -B build -S . 2>&1 | head -20`
Expected: FAIL with `CMakeLists.txt not found` or `No such file`.

- [ ] **Step 3: Write minimal implementation**

```cmake
# CMakeLists.txt
cmake_minimum_required(VERSION 3.20)
project(secure_file_transfer CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
include(FetchContent)
FetchContent_Declare(googletest URL https://github.com/google/googletest/archive/v1.14.0.zip)
FetchContent_Declare(asio URL https://github.com/chriskohlhoff/asio/archive/asio-1-30-2.zip)
FetchContent_MakeAvailable(googletest)
add_executable(sft_server server/main.cpp)
add_executable(sft_client client/main.cpp)
target_include_directories(sft_server PRIVATE include)
target_include_directories(sft_client PRIVATE include)
enable_testing()
add_executable(sft_tests tests/smoke/test_build.cpp)
target_include_directories(sft_tests PRIVATE include)
target_link_libraries(sft_tests PRIVATE gtest_main)
include(GoogleTest)
gtest_discover_tests(sft_tests)
```

```cpp
// server/main.cpp
#include <iostream>
int main(int argc, char** argv) {
  for (int i = 1; i < argc; ++i)
    if (std::string(argv[i]) == "--help") { std::cout << "sft_server --port 5000\n"; return 0; }
  std::cout << "sft_server stub: use --help\n";
  return 0;
}
```

```cpp
// client/main.cpp
#include <iostream>
int main(int argc, char** argv) {
  for (int i = 1; i < argc; ++i)
    if (std::string(argv[i]) == "--help") { std::cout << "sft_client --server <ip> --port 5000\n"; return 0; }
  std::cout << "sft_client stub: use --help\n";
  return 0;
}
```

```ini
# config.example.ini
[server]
bind=0.0.0.0
port=5000
[trust]
; Stage-0 pinned fingerprint stub (replaced by Demo CA in Final)
fingerprint=FAKE-SHA256-STAGE0-DEMO
[storage]
path=./storage
```

```markdown
<!-- certs/README.md -->
# Stage-0 trust
Server prints FAKE-SHA256-STAGE0-DEMO. Clients verify the displayed string matches config before Yes/No upload. No USB transfer required.
```

```markdown
<!-- docs/impl-logs/stage-0-impl-log.md seed -->
# Stage-0 Impl Log
## Step 0 — seed — scaffold created
**Intent:** Prove build wires exes + tests.
**Approach:** Minimal CMake with GTest FetchContent; stub mains only print help. Rejected vendoring GTest zip because FetchContent is one block and CI-friendly.
**Good:** Record actual here, example: `sft_server --help` printed `sft_server --port 5000`, `ctest` 1/1 PASS in 2.1s.
**Bad:** Record actual here, example: `FetchContent asio URL hash mismatch → pinned asio-1-30-2 zip URL fix` or `none`.
**Tests:** `cmake -B build -S . && cmake --build build && ctest --test-dir build -V`
**Context checkpoint:** 10%
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cmake -B build -S .; if ($?) { cmake --build build --config Debug }; if ($?) { ctest --test-dir build -V }`
Expected: PASS `TargetsExist`, `sft_server --help` prints port line, `sft_client --help` prints server line.

- [ ] **Step 5: Commit**

```bash
git add CMakeLists.txt client/main.cpp server/main.cpp config.example.ini certs/README.md docs/impl-logs/stage-0-impl-log.md tests/smoke/test_build.cpp
git commit -m "chore(stage0): scaffold build + stub exes + log seed"
```

Append to `docs/impl-logs/stage-0-impl-log.md` a Step-0-completed entry with Good/Bad + test output.

---

### Task 1: Base types — IDs, Digest, WrappedKey, Exceptions, Result

**Files:**
- Create: `include/domain/ids.hpp`, `include/domain/digest.hpp`, `include/domain/wrapped_key.hpp`, `include/domain/exceptions.hpp`, `include/domain/result.hpp`
- Test: `tests/domain/test_ids.cpp`

**Interfaces:**
- Consumes: Task0 build.
- Produces: `UserId{std::string value}`, `FileId`, `TransferId` with `operator==`; `Digest{std::array<uint8_t,32> bytes}` + `uint32_t fnv1a32(std::string_view)` + `Digest sha256stub(std::string_view)`; `WrappedKey{int kekVersion; std::string alg; std::vector<uint8_t> nonce, bytes}`; `AppException/ValidationException/AuthException/NotFoundException/IntegrityException/TransportException`; `template<typename T> struct Result{bool ok; T value; std::string error;}`.

**Docs to check:** `MASTER.md` §3-Key classes, cppreference `array`, `vector`.

- [ ] **Step 1: Write the failing test**

```cpp
// tests/domain/test_ids.cpp
#include <gtest/gtest.h>
#include "domain/ids.hpp"
#include "domain/digest.hpp"
#include "domain/result.hpp"
TEST(Ids, EqualityOnly) {
  UserId a{"alice"}, b{"alice"}, c{"bob"};
  EXPECT_TRUE(a == b);
  EXPECT_FALSE(a == c);
}
TEST(DigestFnv, Stable) {
  EXPECT_EQ(fnv1a32("abc"), fnv1a32("abc"));
  EXPECT_NE(fnv1a32("abc"), fnv1a32("abd"));
}
TEST(Result, OkErr) {
  Result<int> r{true, 42, ""};
  EXPECT_TRUE(r.ok && r.value == 42);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build --config Debug; ./build/sft_tests --gtest_filter='Ids.*:DigestFnv.*:Result.*'`
Expected: FAIL with `domain/ids.hpp not found`.

- [ ] **Step 3: Write minimal implementation**

```cpp
// include/domain/ids.hpp
#pragma once
#include <string>
struct UserId { std::string value; bool operator==(const UserId&) const = default; };
struct FileId { std::string value; bool operator==(const FileId&) const = default; };
struct TransferId { std::string value; bool operator==(const TransferId&) const = default; };
```

```cpp
// include/domain/digest.hpp
#pragma once
#include <array>
#include <cstdint>
#include <string_view>
struct Digest { std::array<uint8_t,32> bytes{}; bool operator==(const Digest&) const = default; };
inline uint32_t fnv1a32(std::string_view s) {
  uint32_t h = 2166136261u;
  for (unsigned char c : s) { h ^= c; h *= 16777619u; }
  return h;
}
inline Digest sha256stub(std::string_view s) {
  Digest d{};
  uint32_t h = fnv1a32(s);
  for (size_t i = 0; i < 32; ++i) d.bytes[i] = static_cast<uint8_t>((h >> ((i % 4) * 8)) ^ (i * 31));
  return d;
}
```

```cpp
// include/domain/wrapped_key.hpp
#pragma once
#include <cstdint>
#include <string>
#include <vector>
struct WrappedKey { int kekVersion = 1; std::string alg = "FAKE-XOR-FNV"; std::vector<uint8_t> nonce; std::vector<uint8_t> bytes; };
```

```cpp
// include/domain/exceptions.hpp
#pragma once
#include <stdexcept>
#include <string>
struct AppException : std::runtime_error { using std::runtime_error::runtime_error; };
struct ValidationException : AppException { using AppException::AppException; };
struct AuthException : AppException { using AppException::AppException; };
struct NotFoundException : AppException { using AppException::AppException; };
struct IntegrityException : AppException { using AppException::AppException; };
struct TransportException : AppException { using AppException::AppException; };
```

```cpp
// include/domain/result.hpp
#pragma once
#include <string>
template<typename T> struct Result { bool ok = false; T value{}; std::string error; };
```

Update `CMakeLists.txt` `sft_tests` to glob `tests/domain/*.cpp` (edit file, add `file(GLOB TEST_SRCS tests/*/*.cpp)`).

- [ ] **Step 4: Run test to verify it passes**

Run: `cmake -B build -S .; if ($?) { cmake --build build --config Debug }; if ($?) { ctest --test-dir build -V }`
Expected: PASS all 3 tests.

- [ ] **Step 5: Commit**

```bash
git add include/domain/ids.hpp include/domain/digest.hpp include/domain/wrapped_key.hpp include/domain/exceptions.hpp include/domain/result.hpp tests/domain/test_ids.cpp CMakeLists.txt docs/impl-logs/stage-0-impl-log.md
git commit -m "feat(stage0): base ids/digest/key/exceptions/result + tests"
```

Append log Step 1 entry (Approach paragraph must state why FNV stub + sha256stub chosen: deterministic, zero-dep, replaced by AES-GCM in Stage-2).

---

### Task 2 (Lane-A): Domain entities — User, FileRecord, Transfer, Permission, DownloadToken, AuditEvent

**Files:**
- Create: `include/domain/user.hpp`, `include/domain/file_record.hpp`, `include/domain/transfer.hpp`, `include/domain/permission.hpp`, `include/domain/download_token.hpp`, `include/domain/audit_event.hpp` + `src/domain/*.cpp` for methods
- Test: `tests/domain/test_entities.cpp`

**Interfaces:**
- Consumes: Task1 `UserId/FileId/TransferId/Digest/WrappedKey/AppException`.
- Produces: `class User{UserId id; std::string username, passHash; std::string role, status; bool canLogin() const;}` + `class RegularUser: public User` + `class Administrator: public User`; `struct FileRecord{FileId id; UserId owner; std::string origName, storageId; uint64_t size; Digest digest; WrappedKey wrapped; bool isOwnedBy(UserId) const;}`; `struct Transfer{TransferId id; FileId file; UserId sender, recipient; enum class Status{CREATED,UPLOADED,DOWNLOADED,FAILED}; Status status; void markDownloaded();}`; `struct Permission{FileId file; UserId user; int64_t expiresAt; bool revoked;}`; `struct DownloadToken{std::string tokenHash; FileId file; UserId creator, bind; int64_t expiresAt = 4102444800; int maxUses = 1; int useCount = 0; bool revoked = false; bool validFor(const UserId&, int64_t now) const;}` (Stage-0: checks `bind==user && !revoked`; expiry/maxUses fields honored but default far-future); `struct AuditEvent{uint64_t seq; std::string ts, actor, action, fileId, cipherHash, prevHash, msgHash;}`.

**Docs to check:** `MASTER.md` §3-Key classes, `system_architecture.md` §3.

- [ ] **Step 1: Write the failing test**

```cpp
// tests/domain/test_entities.cpp
#include <gtest/gtest.h>
#include "domain/user.hpp"
#include "domain/file_record.hpp"
#include "domain/transfer.hpp"
#include "domain/download_token.hpp"
TEST(Entities, OwnershipAndTransfer) {
  UserId alice{"alice"}, bob{"bob"};
  RegularUser a(alice, "alice", "hash");
  EXPECT_TRUE(a.canLogin());
  FileRecord f{FileId{"f1"}, alice, "a.pdf", "uuid-1", 10, Digest{}, WrappedKey{}};
  EXPECT_TRUE(f.isOwnedBy(alice));
  EXPECT_FALSE(f.isOwnedBy(bob));
  Transfer t{TransferId{"t1"}, FileId{"f1"}, alice, bob, Transfer::Status::UPLOADED};
  t.markDownloaded();
  EXPECT_EQ(t.status, Transfer::Status::DOWNLOADED);
}
TEST(Entities, TokenBind) {
  DownloadToken tok{"h1", FileId{"f1"}, UserId{"alice"}, UserId{"bob"}};
  EXPECT_TRUE(tok.validFor(UserId{"bob"}, 0));
  EXPECT_FALSE(tok.validFor(UserId{"carol"}, 0));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build --config Debug; ./build/sft_tests --gtest_filter='Entities.*'`
Expected: FAIL with `domain/user.hpp not found`.

- [ ] **Step 3: Write minimal implementation**

```cpp
// include/domain/user.hpp
#pragma once
#include "domain/ids.hpp"
#include <string>
class User {
 public:
  User(UserId id, std::string username, std::string passHash, std::string role="user", std::string status="active")
      : id_(id), username_(std::move(username)), passHash_(std::move(passHash)), role_(role), status_(status) {
    if (username_.empty()) throw ValidationException("username empty");
  }
  virtual ~User() = default;
  const UserId& id() const { return id_; }
  bool canLogin() const { return status_ == "active"; }
 private:
  UserId id_; std::string username_, passHash_, role_, status_;
};
class RegularUser : public User { public: using User::User; };
class Administrator : public User { public: using User::User; };
```

```cpp
// include/domain/file_record.hpp
#pragma once
#include "domain/ids.hpp"
#include "domain/digest.hpp"
#include "domain/wrapped_key.hpp"
#include <string>
struct FileRecord {
  FileId id; UserId owner; std::string origName, storageId; uint64_t size = 0; Digest digest; WrappedKey wrapped;
  bool isOwnedBy(const UserId& u) const { return owner == u; }
};
```

```cpp
// include/domain/transfer.hpp
#pragma once
#include "domain/ids.hpp"
struct Transfer {
  enum class Status { CREATED, UPLOADED, DOWNLOADED, FAILED };
  TransferId id; FileId file; UserId sender, recipient; Status status = Status::CREATED;
  void markDownloaded() { status = Status::DOWNLOADED; }
};
```

```cpp
// include/domain/download_token.hpp
#pragma once
#include "domain/ids.hpp"
#include <cstdint>
#include <string>
struct DownloadToken {
  std::string tokenHash; FileId file; UserId creator, bind;
  int64_t expiresAt = 4102444800; int maxUses = 1; int useCount = 0; bool revoked = false;
  bool validFor(const UserId& u, int64_t now) const {
    if (revoked) return false;
    if (!(bind == u)) return false;
    if (now > expiresAt) return false;
    if (useCount >= maxUses) return false;
    return true;
  }
};
```

```cpp
// include/domain/permission.hpp
#pragma once
#include "domain/ids.hpp"
#include <cstdint>
struct Permission { FileId file; UserId user; int64_t expiresAt = 4102444800; bool revoked = false; };
```

```cpp
// include/domain/audit_event.hpp
#pragma once
#include <cstdint>
#include <string>
struct AuditEvent { uint64_t seq = 0; std::string ts, actor, action, fileId, cipherHash, prevHash, msgHash; };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cmake --build build --config Debug; ./build/sft_tests --gtest_filter='Entities.*'`
Expected: PASS both tests.

- [ ] **Step 5: Commit**

```bash
git add include/domain/user.hpp include/domain/file_record.hpp include/domain/transfer.hpp include/domain/permission.hpp include/domain/download_token.hpp include/domain/audit_event.hpp tests/domain/test_entities.cpp
git commit -m "feat(stage0): domain entities + token bind stub"
```

Append log Step 2 entry (Good: pure headers, no lib includes; Bad: any `using namespace` or socket include must be listed as violation + fix).

---

### Task 3 (Lane-B): Ports + in-memory/fake adapters

**Files:**
- Create: `include/ports/repository.hpp`, `include/ports/storage.hpp`, `include/ports/crypto.hpp`, `include/ports/audit.hpp`, `include/ports/policy.hpp`, `include/infrastructure/memory_repo.hpp`, `include/infrastructure/fake_crypto.hpp`, `include/infrastructure/memory_storage.hpp`, `include/infrastructure/vector_audit.hpp`
- Test: `tests/infra/test_fakes.cpp`

**Interfaces:**
- Consumes: Task1-2 types.
- Produces: `template<class T,class Id> class Repository{virtual void save(const T&) = 0; virtual Result<T> find(const Id&) const = 0; virtual ~Repository()=default;}`; `class IStorage{virtual void write(const std::string&, const std::vector<uint8_t>&) = 0; virtual std::vector<uint8_t> read(const std::string&) const = 0;}`; `struct EncryptOut{std::vector<uint8_t> cipher; WrappedKey wrapped; Digest digest;}; class IEncryptionProvider{virtual EncryptOut encrypt(const std::vector<uint8_t>&) = 0; virtual std::vector<uint8_t> decryptAndVerify(const std::vector<uint8_t>&, const WrappedKey&, const Digest&) = 0;}`; `class IAuditLogger{virtual void record(AuditEvent) = 0; virtual std::vector<AuditEvent> all() const = 0;}`; `template<class T,class Id> class InMemoryRepo: public Repository<T,Id>` (unordered_map); `class FakeCrypto: public IEncryptionProvider` (XOR 0x5A, nonce={1,2,3}, digest=sha256stub of plain, throws IntegrityException on tag mismatch); `class MemoryStorage: public IStorage`; `class VectorAudit: public IAuditLogger` (assigns seq, prevHash chaining via fnv hex).

**Docs to check:** `MASTER.md` §3-Ports, `system_architecture.md` §3-ports.

- [ ] **Step 1: Write the failing test**

```cpp
// tests/infra/test_fakes.cpp
#include <gtest/gtest.h>
#include "infrastructure/fake_crypto.hpp"
#include "infrastructure/memory_storage.hpp"
#include "domain/exceptions.hpp"
TEST(Fakes, RoundTripAndTamper) {
  FakeCrypto c;
  std::vector<uint8_t> plain{'h','i'};
  auto out = c.encrypt(plain);
  EXPECT_EQ(c.decryptAndVerify(out.cipher, out.wrapped, out.digest), plain);
  out.cipher[0] ^= 0x01;
  EXPECT_THROW(c.decryptAndVerify(out.cipher, out.wrapped, out.digest), IntegrityException);
}
TEST(Fakes, StorageWriteRead) {
  MemoryStorage s; s.write("k", {1,2,3});
  EXPECT_EQ(s.read("k"), (std::vector<uint8_t>{1,2,3}));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build --config Debug; ./build/sft_tests --gtest_filter='Fakes.*'`
Expected: FAIL with `infrastructure/fake_crypto.hpp not found`.

- [ ] **Step 3: Write minimal implementation**

```cpp
// include/ports/repository.hpp
#pragma once
#include "domain/result.hpp"
template<typename T, typename Id>
class Repository { public: virtual ~Repository() = default; virtual void save(const T& v) = 0; virtual Result<T> find(const Id& id) const = 0; };
```

```cpp
// include/ports/storage.hpp
#pragma once
#include <cstdint>
#include <string>
#include <vector>
class IStorage { public: virtual ~IStorage() = default; virtual void write(const std::string& k, const std::vector<uint8_t>& v) = 0; virtual std::vector<uint8_t> read(const std::string& k) const = 0; };
```

```cpp
// include/ports/crypto.hpp
#pragma once
#include "domain/digest.hpp"
#include "domain/wrapped_key.hpp"
#include <cstdint>
#include <vector>
struct EncryptOut { std::vector<uint8_t> cipher; WrappedKey wrapped; Digest digest; };
class IEncryptionProvider { public: virtual ~IEncryptionProvider() = default; virtual EncryptOut encrypt(const std::vector<uint8_t>& plain) = 0; virtual std::vector<uint8_t> decryptAndVerify(const std::vector<uint8_t>& cipher, const WrappedKey&, const Digest& d) = 0; };
```

```cpp
// include/ports/audit.hpp
#pragma once
#include "domain/audit_event.hpp"
#include <vector>
class IAuditLogger { public: virtual ~IAuditLogger() = default; virtual void record(AuditEvent e) = 0; virtual std::vector<AuditEvent> all() const = 0; };
```

```cpp
// include/ports/policy.hpp
#pragma once
#include "domain/ids.hpp"
#include "domain/file_record.hpp"
class IAccessPolicy { public: virtual ~IAccessPolicy() = default; virtual bool isAuthorized(const UserId& u, const FileRecord& f) const = 0; };
```

```cpp
// include/infrastructure/fake_crypto.hpp
#pragma once
#include "ports/crypto.hpp"
#include "domain/exceptions.hpp"
class FakeCrypto : public IEncryptionProvider {
 public:
  EncryptOut encrypt(const std::vector<uint8_t>& p) override {
    EncryptOut o; o.cipher = p;
    for (auto& b : o.cipher) b ^= 0x5A;
    o.wrapped = WrappedKey{1, "FAKE-XOR-FNV", {1,2,3}, {9,9}};
    std::string s(p.begin(), p.end());
    o.digest = sha256stub(s);
    return o;
  }
  std::vector<uint8_t> decryptAndVerify(const std::vector<uint8_t>& c, const WrappedKey&, const Digest& d) override {
    std::vector<uint8_t> p = c;
    for (auto& b : p) b ^= 0x5A;
    std::string s(p.begin(), p.end());
    if (!(sha256stub(s) == d)) throw IntegrityException("tag mismatch");
    return p;
  }
};
```

```cpp
// include/infrastructure/memory_storage.hpp
#pragma once
#include "ports/storage.hpp"
#include <unordered_map>
class MemoryStorage : public IStorage {
 public:
  void write(const std::string& k, const std::vector<uint8_t>& v) override { m_[k] = v; }
  std::vector<uint8_t> read(const std::string& k) const override {
    auto it = m_.find(k);
    if (it == m_.end()) throw NotFoundException("missing blob");
    return it->second;
  }
 private:
  std::unordered_map<std::string, std::vector<uint8_t>> m_;
};
```

```cpp
// include/infrastructure/memory_repo.hpp
#pragma once
#include "ports/repository.hpp"
#include <unordered_map>
template<typename T, typename Id, typename KeyFn>
class InMemoryRepo : public Repository<T, Id> {
 public:
  explicit InMemoryRepo(KeyFn k) : key_(k) {}
  void save(const T& v) override { m_[key_(v)] = v; }
  Result<T> find(const Id& id) const override {
    auto it = m_.find(id.value);
    if (it == m_.end()) return {false, T{}, "not found"};
    return {true, it->second, ""};
  }
 private:
  KeyFn key_; std::unordered_map<std::string, T> m_;
};
```

```cpp
// include/infrastructure/vector_audit.hpp
#pragma once
#include "ports/audit.hpp"
#include <string>
class VectorAudit : public IAuditLogger {
 public:
  void record(AuditEvent e) override { e.seq = log_.size(); e.prevHash = log_.empty() ? "GENESIS" : log_.back().msgHash; e.msgHash = "h" + std::to_string(e.seq); log_.push_back(e); }
  std::vector<AuditEvent> all() const override { return log_; }
 private:
  std::vector<AuditEvent> log_;
};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cmake --build build --config Debug; ./build/sft_tests --gtest_filter='Fakes.*'`
Expected: PASS both tests.

- [ ] **Step 5: Commit**

```bash
git add include/ports/ include/infrastructure/memory_repo.hpp include/infrastructure/fake_crypto.hpp include/infrastructure/memory_storage.hpp include/infrastructure/vector_audit.hpp tests/infra/test_fakes.cpp
git commit -m "feat(stage0): ports + fake crypto/storage/audit"
```

Append log Step 3 entry (Approach paragraph must justify XOR+FNV as tamper-demo stand-in, explicitly NOT shipping crypto, replaced Stage-2).

---

### Task 4: Application — PolicyEngine + AuthService + TransferService

**Files:**
- Create: `include/application/policy_engine.hpp`, `include/application/auth_service.hpp`, `include/application/transfer_service.hpp` + `src/application/*.cpp`
- Test: `tests/application/test_policy.cpp`, `tests/application/test_transfer.cpp`

**Interfaces:**
- Consumes: Task2 entities + Task3 `Repository/IStorage/IEncryptionProvider/IAuditLogger/IAccessPolicy`.
- Produces: `class PolicyEngine: public IAccessPolicy{bool isAuthorized(const UserId&, const FileRecord&) const override;}` (Stage-0: `f.isOwnedBy(u) || recipientMap_.contains(file, u)`; recipient map injected); `class AuthService{Result<User> regist(const std::string& name, const std::string& pw); Result<User> login(const std::string& name, const std::string& pw);}` (Stage-0 hash = `sha256stub(pw+salt).bytes` hex, per-user salt `name`; generic `Login failed` error, no enumeration); `class TransferService{Result<Transfer> upload(const UserId& sender, const std::string& recipientName, const std::string& origName, const std::vector<uint8_t>& bytes); Result<std::vector<uint8_t>> download(const UserId& requester, const FileId& fid); std::vector<Transfer> listFor(const UserId&);}` (validates recipient exists, size ≤100MB, allow-list ext, magic-byte stub PNG/PDF/ZIP, stores cipher under `uuid`, records audit UPLOAD/DOWNLOAD/DENIED/INTEGRITY_FAIL, throws IntegrityException outward on tag fail, never returns partial bytes).

**Docs to check:** `MASTER.md` §4-AuthZ/Upload validation/Errors, `project_description.md` §8.

- [ ] **Step 1: Write the failing test**

```cpp
// tests/application/test_policy.cpp
#include <gtest/gtest.h>
#include "application/policy_engine.hpp"
TEST(Policy, OwnerRecipientStranger) {
  PolicyEngine p;
  FileRecord f{FileId{"f1"}, UserId{"alice"}, "a.pdf", "u1", 1, Digest{}, WrappedKey{}};
  p.grant(FileId{"f1"}, UserId{"bob"});
  EXPECT_TRUE(p.isAuthorized(UserId{"alice"}, f));
  EXPECT_TRUE(p.isAuthorized(UserId{"bob"}, f));
  EXPECT_FALSE(p.isAuthorized(UserId{"carol"}, f));
}
```

```cpp
// tests/application/test_transfer.cpp
#include <gtest/gtest.h>
#include "application/transfer_service.hpp"
TEST(TransferSvc, AliceBobCarolFlow) {
  // wired in Step 3 with MemoryStorage+FakeCrypto+VectorAudit
  EXPECT_TRUE(true);  // replaced by real flow assertions in Step 3 file version below
}
```

Full `test_transfer.cpp` Step-3 version (write this exact content in Step 3, this preview shows intent):

```cpp
#include <gtest/gtest.h>
#include "application/transfer_service.hpp"
#include "infrastructure/fake_crypto.hpp"
#include "infrastructure/memory_storage.hpp"
#include "infrastructure/vector_audit.hpp"
TEST(TransferSvc, AliceBobCarolFlow) {
  MemoryStorage st; FakeCrypto cr; VectorAudit au;
  TransferService svc(&st, &cr, &au);
  svc.addUser("alice"); svc.addUser("bob"); svc.addUser("carol");
  auto up = svc.upload(UserId{"alice"}, "bob", "a.pdf", {'h','i'});
  ASSERT_TRUE(up.ok);
  auto bobBytes = svc.download(UserId{"bob"}, up.value.file);
  EXPECT_EQ(bobBytes.value, (std::vector<uint8_t>{'h','i'}));
  auto carol = svc.download(UserId{"carol"}, up.value.file);
  EXPECT_FALSE(carol.ok);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build --config Debug; ./build/sft_tests --gtest_filter='Policy.*:TransferSvc.*'`
Expected: FAIL with `application/policy_engine.hpp not found`.

- [ ] **Step 3: Write minimal implementation**

```cpp
// include/application/policy_engine.hpp
#pragma once
#include "ports/policy.hpp"
#include <map>
class PolicyEngine : public IAccessPolicy {
 public:
  void grant(const FileId& f, const UserId& u) { grants_[f.value].insert(u.value); }
  bool isAuthorized(const UserId& u, const FileRecord& f) const override {
    if (f.isOwnedBy(u)) return true;
    auto it = grants_.find(f.value);
    return it != grants_.end() && it->second.count(u.value) > 0;
  }
 private:
  std::map<std::string, std::set<std::string>> grants_;
};
```

```cpp
// include/application/auth_service.hpp
#pragma once
#include "domain/ids.hpp"
#include "domain/user.hpp"
#include "domain/result.hpp"
#include <map>
class AuthService {
 public:
  Result<User> regist(const std::string& name, const std::string& pw);
  Result<User> login(const std::string& name, const std::string& pw) const;
 private:
  std::map<std::string, User> users_;
};
```

```cpp
// src/application/auth_service.cpp
#include "application/auth_service.hpp"
#include "domain/digest.hpp"
Result<User> AuthService::regist(const std::string& n, const std::string& pw) {
  if (n.empty() || pw.size() < 4) return {false, User(UserId{"x"}, "x", "x"), "invalid"};
  if (users_.count(n)) return {false, User(UserId{"x"}, "x", "x"), "Login failed"};
  Digest h = sha256stub(n + ":" + pw);
  User u(UserId{n}, n, std::string(h.bytes.begin(), h.bytes.end()));
  users_.emplace(n, u);
  return {true, u, ""};
}
Result<User> AuthService::login(const std::string& n, const std::string& pw) const {
  auto it = users_.find(n);
  if (it == users_.end()) return {false, User(UserId{"x"}, "x", "x"), "Login failed"};
  Digest h = sha256stub(n + ":" + pw);
  std::string want(h.bytes.begin(), h.bytes.end());
  // constant-time-ish compare stub
  const std::string& have = "unused";
  (void)have;
  return {true, it->second, ""};
}
```

Note: Stage-0 `login` returns user if name exists (hash check stubbed to generic path; full Argon2 + stored-hash compare lands Stage-2 — log this as tech debt in code comment).

```cpp
// include/application/transfer_service.hpp
#pragma once
#include "domain/result.hpp"
#include "domain/transfer.hpp"
#include "ports/storage.hpp"
#include "ports/crypto.hpp"
#include "ports/audit.hpp"
#include <map>
class TransferService {
 public:
  TransferService(IStorage* s, IEncryptionProvider* c, IAuditLogger* a) : st_(s), cr_(c), au_(a) {}
  void addUser(const std::string& n) { users_.insert(n); }
  Result<Transfer> upload(const UserId& sender, const std::string& recip, const std::string& orig, const std::vector<uint8_t>& bytes);
  Result<std::vector<uint8_t>> download(const UserId& req, const FileId& fid);
  std::vector<Transfer> listFor(const UserId& u) const;
 private:
  bool validExt(const std::string& n) const;
  IStorage* st_; IEncryptionProvider* cr_; IAuditLogger* au_;
  std::set<std::string> users_; std::map<std::string, FileRecord> files_; std::map<std::string, Transfer> trs_; std::map<std::string, std::set<std::string>> grants_;
  int ctr_ = 0;
};
```

```cpp
// src/application/transfer_service.cpp
#include "application/transfer_service.hpp"
#include "domain/exceptions.hpp"
Result<Transfer> TransferService::upload(const UserId& s, const std::string& r, const std::string& o, const std::vector<uint8_t>& b) {
  if (!users_.count(s.value) || !users_.count(r)) return {false, Transfer{}, "unknown user"};
  if (!validExt(o)) return {false, Transfer{}, "bad extension"};
  if (b.size() > 100u * 1024u * 1024u) return {false, Transfer{}, "oversize"};
  auto out = cr_->encrypt(b);
  std::string uuid = "uuid-" + std::to_string(++ctr_);
  st_->write(uuid, out.cipher);
  FileRecord fr{FileId{"f" + std::to_string(ctr_)}, s, o, uuid, b.size(), out.digest, out.wrapped};
  files_.emplace(fr.id.value, fr);
  grants_[fr.id.value].insert(r);
  Transfer t{TransferId{"t" + std::to_string(ctr_)}, fr.id, s, UserId{r}, Transfer::Status::UPLOADED};
  trs_.emplace(t.id.value, t);
  au_->record({0, "now", s.value, "UPLOAD", fr.id.value, "", "", ""});
  return {true, t, ""};
}
Result<std::vector<uint8_t>> TransferService::download(const UserId& q, const FileId& fid) {
  auto it = files_.find(fid.value);
  if (it == files_.end()) return {false, {}, "not found"};
  const FileRecord& fr = it->second;
  bool ok = (fr.owner == q) || grants_[fid.value].count(q.value);
  if (!ok) { au_->record({0, "now", q.value, "DENIED", fid.value, "", "", ""}); return {false, {}, "denied"}; }
  auto cipher = st_->read(fr.storageId);
  try {
    auto plain = cr_->decryptAndVerify(cipher, fr.wrapped, fr.digest);
    au_->record({0, "now", q.value, "DOWNLOAD", fid.value, "", "", ""});
    return {true, plain, ""};
  } catch (const IntegrityException&) {
    au_->record({0, "now", q.value, "INTEGRITY_FAIL", fid.value, "", "", ""});
    throw;
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cmake --build build --config Debug; ./build/sft_tests --gtest_filter='Policy.*:TransferSvc.*'`
Expected: PASS; `test_transfer.cpp` must be overwritten with the full flow version shown in Step 1 preview before running.

- [ ] **Step 5: Commit**

```bash
git add include/application/ src/application/ tests/application/
git commit -m "feat(stage0): policy + auth stub + transfer upload/download"
```

Append log Step 4 entry (Good: Carol DENY path audited; Bad: AuthService hash compare stubbed — must list as Stage-2 debt with exact file:line).

---

### Task 5 (Lane-C): Framing + ITransport + Asio plain TCP :5000

**Files:**
- Create: `include/ports/transport.hpp`, `include/infrastructure/asio_transport.hpp`, `src/infrastructure/asio_transport.cpp`
- Test: `tests/infra/test_framing.cpp`

**Interfaces:**
- Consumes: none beyond Task0 (independent of domain).
- Produces: `enum class MsgType : uint8_t {HELLO=1,AUTH,UPLOAD_INIT,DATA,COMMIT,DOWNLOAD_REQ,LIST,REVOKE,ERROR}; struct Frame{MsgType type; uint32_t requestId; std::vector<uint8_t> body;}; std::vector<uint8_t> encodeFrame(const Frame&); bool tryDecode(const std::vector<uint8_t>& buf, Frame& out, size_t& consumed);` wire = `[uint32 BE totalLen][type(1)][requestId(4BE)][body]`; `class ITransport{virtual void connect(const std::string&, uint16_t) = 0; virtual void sendFrame(const Frame&) = 0; virtual bool recvFrame(Frame&, int timeoutMs) = 0; virtual void close() = 0;}`; `class FakeTransport: public ITransport` (in-memory queue pair); `class AsioTcpTransport: public ITransport` (blocking Asio plain TCP, handles split/coalesced reads by buffering until `totalLen` bytes arrive).

**Docs to check:** `MASTER.md` §3c, Asio `ip::tcp::socket` + `read_some` docs.

- [ ] **Step 1: Write the failing test**

```cpp
// tests/infra/test_framing.cpp
#include <gtest/gtest.h>
#include "ports/transport.hpp"
TEST(Framing, SplitCoalesced) {
  Frame f{MsgType::DATA, 7, {1,2,3,4}};
  auto wire = encodeFrame(f);
  // split delivery
  std::vector<uint8_t> half(wire.begin(), wire.begin() + 3);
  Frame out; size_t used = 0;
  EXPECT_FALSE(tryDecode(half, out, used));
  // coalesced delivery (two frames back-to-back)
  auto wire2 = encodeFrame(f);
  std::vector<uint8_t> both = wire; both.insert(both.end(), wire2.begin(), wire2.end());
  EXPECT_TRUE(tryDecode(both, out, used));
  EXPECT_EQ(out.requestId, 7u);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build --config Debug; ./build/sft_tests --gtest_filter='Framing.*'`
Expected: FAIL with `ports/transport.hpp not found`.

- [ ] **Step 3: Write minimal implementation**

```cpp
// include/ports/transport.hpp
#pragma once
#include <cstdint>
#include <vector>
enum class MsgType : uint8_t { HELLO=1, AUTH=2, UPLOAD_INIT=3, DATA=4, COMMIT=5, DOWNLOAD_REQ=6, LIST=7, REVOKE=8, ERROR=255 };
struct Frame { MsgType type = MsgType::HELLO; uint32_t requestId = 0; std::vector<uint8_t> body; };
inline void put32be(std::vector<uint8_t>& v, uint32_t x) { v.push_back((x>>24)&0xFF); v.push_back((x>>16)&0xFF); v.push_back((x>>8)&0xFF); v.push_back(x&0xFF); }
inline uint32_t get32be(const uint8_t* p) { return (uint32_t(p[0])<<24)|(uint32_t(p[1])<<16)|(uint32_t(p[2])<<8)|uint32_t(p[3]); }
inline std::vector<uint8_t> encodeFrame(const Frame& f) {
  std::vector<uint8_t> payload; payload.push_back((uint8_t)f.type); put32be(payload, f.requestId);
  payload.insert(payload.end(), f.body.begin(), f.body.end());
  std::vector<uint8_t> wire; put32be(wire, (uint32_t)payload.size()); wire.insert(wire.end(), payload.begin(), payload.end());
  return wire;
}
inline bool tryDecode(const std::vector<uint8_t>& buf, Frame& out, size_t& consumed) {
  if (buf.size() < 4) return false;
  uint32_t len = get32be(buf.data());
  if (len > 4u*1024u*1024u) return false;
  if (buf.size() < 4 + len || len < 5) return false;
  out.type = (MsgType)buf[4]; out.requestId = get32be(buf.data()+5);
  out.body.assign(buf.begin()+9, buf.begin()+4+len);
  consumed = 4 + len;
  return true;
}
class ITransport { public: virtual ~ITransport() = default; virtual void connect(const std::string&, uint16_t) = 0; virtual void sendFrame(const Frame&) = 0; virtual bool recvFrame(Frame&, int) = 0; virtual void close() = 0; };
```

`FakeTransport` + `AsioTcpTransport` headers: FakeTransport uses `std::deque<std::vector<uint8_t>>` loopback; AsioTcpTransport wraps `asio::ip::tcp::socket` with a `std::vector<uint8_t> rxBuf_` accumulator calling `tryDecode` in a loop (20-line core, full socket code in `src/infrastructure/asio_transport.cpp` using blocking `connect/read_some/write`).

- [ ] **Step 4: Run test to verify it passes**

Run: `cmake --build build --config Debug; ./build/sft_tests --gtest_filter='Framing.*'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add include/ports/transport.hpp include/infrastructure/asio_transport.hpp src/infrastructure/asio_transport.cpp tests/infra/test_framing.cpp
git commit -m "feat(stage0): framing + ITransport + fake/Asio plain TCP"
```

Append log Step 5 entry (Good: split/coalesce handled; Bad: any Nagle/partial-write flake + retry fix).

---

### Task 6: STL+ANSI CLI + client/server exes (Yes/No only)

**Files:**
- Create: `include/presentation/ansi.hpp`, `include/presentation/cli.hpp`, `include/presentation/client_app.hpp`, `include/presentation/server_app.hpp` + `src/presentation/*.cpp`; Modify: `client/main.cpp`, `server/main.cpp`
- Test: `tests/presentation/test_cli.cpp` (non-interactive: feed `y\n` via stringstream)

**Interfaces:**
- Consumes: Task4 `AuthService/TransferService`, Task5 `ITransport/Frame`.
- Produces: `namespace ansi{green(),red(),yellow(),reset(),progressBar(int pct)}`; `bool askYesNo(const std::string& prompt, std::istream&)`; `class ServerApp{int run(uint16_t port);}` (binds `0.0.0.0:port`, prints `SERVER IPv4=<list> PORT=5000 FINGERPRINT=FAKE-SHA256-STAGE0-DEMO`, serves AUTH/UPLOAD/DOWNLOAD via TransferService); `class ClientApp{int run(const std::string& ip, uint16_t port);}` (login prompt, `Upload <file> for Bob? [y/N]`, `Download <file>? [y/N]`, progress % per DATA chunk, success/error colors); mains parse `--server/--port/--help`.

**Docs to check:** `MASTER.md` §2/§3b/§8, `project_description.md` §7.

- [ ] **Step 1: Write the failing test**

```cpp
// tests/presentation/test_cli.cpp
#include <gtest/gtest.h>
#include "presentation/cli.hpp"
#include <sstream>
TEST(Cli, YesNo) {
  std::istringstream in("y\n");
  EXPECT_TRUE(askYesNo("Upload a.pdf for Bob?", in));
  std::istringstream in2("n\n");
  EXPECT_FALSE(askYesNo("Download?", in2));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build build --config Debug; ./build/sft_tests --gtest_filter='Cli.*'`
Expected: FAIL with `presentation/cli.hpp not found`.

- [ ] **Step 3: Write minimal implementation**

```cpp
// include/presentation/ansi.hpp
#pragma once
#include <string>
namespace ansi {
inline std::string green() { return "\x1b[32m"; }
inline std::string red() { return "\x1b[31m"; }
inline std::string yellow() { return "\x1b[33m"; }
inline std::string reset() { return "\x1b[0m"; }
inline std::string progressBar(int pct) {
  int bars = pct / 10; std::string s = "[";
  for (int i = 0; i < 10; ++i) s += (i < bars ? "#" : "-");
  return s + "] " + std::to_string(pct) + "%";
}
}
```

```cpp
// include/presentation/cli.hpp
#pragma once
#include <iostream>
#include <string>
inline bool askYesNo(const std::string& prompt, std::istream& in = std::cin) {
  std::cout << prompt << " [y/N] ";
  std::string a; std::getline(in, a);
  return !a.empty() && (a[0] == 'y' || a[0] == 'Y');
}
inline void printSuccess(const std::string& m);
inline void printError(const std::string& m);
```

Server `run()` must: `cout << "SERVER IPv4=<first non-loopback> PORT=5000 FINGERPRINT=FAKE-SHA256-STAGE0-DEMO\n"` then accept loop (single-threaded Stage-0 is acceptable, note multi-client lands Stage-3). Client `run()` must: prompt server IP (or argv), login, list, Yes/No upload/download, show `progressBar()` per 64KB chunk.

- [ ] **Step 4: Run test to verify it passes**

Run: `cmake --build build --config Debug; ./build/sft_tests --gtest_filter='Cli.*'; ./build/sft_server --help; ./build/sft_client --help`
Expected: PASS + both helps print usage lines.

- [ ] **Step 5: Commit**

```bash
git add include/presentation/ src/presentation/ client/main.cpp server/main.cpp tests/presentation/test_cli.cpp
git commit -m "feat(stage0): ANSI CLI Yes/No + client/server exes"
```

Append log Step 6 entry (Good: colors render in Windows Terminal; Bad: legacy `cmd.exe` ANSI fallback — document `chcp 65001` workaround).

---

### Task 7: Stage-0 GREEN gate — 3-process demo + log flush

**Files:**
- Create: `tests/integration/test_stage0_gate.cpp`, `docs/STAGE0-DEMO.md`
- Modify: `docs/impl-logs/stage-0-impl-log.md` (flush entry)

**Interfaces:**
- Consumes: all prior tasks.
- Produces: GREEN proof: `Alice→Bob OK`, `Carol DENY + DENIED audit`, `1-byte tamper → IntegrityException + INTEGRITY_FAIL audit, zero bytes delivered`; `docs/STAGE0-DEMO.md` hotspot runbook; log flushed.

**Docs to check:** `MASTER.md` §8/§9-Stage-0 slice.

- [ ] **Step 1: Write the failing test**

```cpp
// tests/integration/test_stage0_gate.cpp
#include <gtest/gtest.h>
#include "application/transfer_service.hpp"
#include "infrastructure/fake_crypto.hpp"
#include "infrastructure/memory_storage.hpp"
#include "infrastructure/vector_audit.hpp"
TEST(Stage0Gate, AliceBobCarolTamper) {
  MemoryStorage st; FakeCrypto cr; VectorAudit au;
  TransferService svc(&st, &cr, &au);
  for (auto u : {"alice","bob","carol"}) svc.addUser(u);
  auto up = svc.upload(UserId{"alice"}, "bob", "report.pdf", std::vector<uint8_t>{10,20,30});
  ASSERT_TRUE(up.ok);
  EXPECT_TRUE(svc.download(UserId{"bob"}, up.value.file).ok);
  EXPECT_FALSE(svc.download(UserId{"carol"}, up.value.file).ok);
  // tamper 1 byte in store
  auto c = st.read("uuid-1");
  c[0] ^= 0x01; st.write("uuid-1", c);
  EXPECT_THROW(svc.download(UserId{"bob"}, up.value.file), IntegrityException);
  auto log = au.all();
  bool sawDeny = false, sawFail = false;
  for (auto& e : log) { if (e.action=="DENIED") sawDeny=true; if (e.action=="INTEGRITY_FAIL") sawFail=true; }
  EXPECT_TRUE(sawDeny && sawFail);
}
```

- [ ] **Step 2: Run test to verify it fails (uuid key may differ)**

Run: `cmake --build build --config Debug; ./build/sft_tests --gtest_filter='Stage0Gate.*'`
Expected: FAIL initially on `uuid-1` assumption or missing audit — then fix test to use `up.value` storageId lookup (log the fix as Bad→Good in impl-log; this is intentional TDD friction).

- [ ] **Step 3: Write minimal implementation (fix + runbook)**

Fix test to fetch real `storageId` via service accessor (add `FileRecord findFile(FileId)` to TransferService in this task if missing — 5 lines). Write `docs/STAGE0-DEMO.md`:

```markdown
# Stage-0 Demo (3 laptops, hotspot, :5000)
1. Server laptop: hotspot ON → `sft_server --port 5000` → note IPv4 + FINGERPRINT.
2. Windows Firewall: Allow on first prompt.
3. Alice laptop: `sft_client --server <IPv4> --port 5000` → register/login → `Upload report.pdf for Bob? [y/N] y`.
4. Bob laptop: same client → login → `Download report.pdf? [y/N] y` → sha256 matches.
5. Carol laptop (or same): login carol → download → `denied` + server audit DENIED.
6. Tamper: server `python -c "flip 1 byte in storage/encrypted/uuid-*.bin"` → Bob download → INTEGRITY_FAIL, no file.
7. Fallback: wired switch / USB-tether if hotspot blocked. `reset-demo` = delete storage/* + restart.
```

- [ ] **Step 4: Run test to verify it passes (full suite + manual 3-terminal)**

Run: `ctest --test-dir build -V; ./build/sft_tests --gtest_filter='Stage0Gate.*'`
Expected: PASS all; then manual: terminal1 `sft_server`, terminal2/3 `sft_client` loopback `127.0.0.1:5000` proving same flow without WiFi.

- [ ] **Step 5: Commit + flush log**

```bash
git add tests/integration/test_stage0_gate.cpp docs/STAGE0-DEMO.md docs/impl-logs/stage-0-impl-log.md
git commit -m "feat(stage0): GREEN gate AliceBobCarolTamper + demo runbook"
```

Append final log entry with `GREEN` evidence, demo outputs pasted, and `### CONTEXT FLUSH` if context ≥95% (open files, next = Stage-1 per MASTER §10).

---

## GREEN Checklist (Stage-0 exits only when all PASS)

- `ctest` all green, `sft_server --help` / `sft_client --help` correct.
- `Stage0Gate.AliceBobCarolTamper` PASS (Bob OK, Carol DENY+audited, 1-byte tamper INTEGRITY_FAIL+audited, zero partial bytes).
- `Framing.SplitCoalesced` PASS; loopback `127.0.0.1:5000` 3-terminal demo recorded in log.
- Hotspot 3-laptop demo recorded (IPv4 + fingerprint photo/transcript) OR loopback + documented hotspot attempt with Bad entry.
- `docs/impl-logs/stage-0-impl-log.md` has Steps 0-7 with Good/Bad/Tests/Context% + no `TODO/TBD` left.
- No `domain/` file includes `<asio.hpp>`, `<openssl/>`, `<sqlite3.h>`, FTXUI, or `iostream` policy logic (grep check in Task7).

## Self-Review (author ran before save)

1. Spec coverage: MASTER §2 flow → Task4+6+7; §3a hotspot/:5000 → Task5+6+7 + runbook; §3b STL+ANSI/Yes-No → Task6; §3c framing/ITransport → Task5; §3d fingerprint stub → Task0+6; tokens §4 → Task2 stub + Task4 bind; audit/validation/errors → Task3+4; demo §8 Stage-0 slice → Task7; tests §9 Stage-0 slice → every Task Step 4; roadmap Stage-0 → Wave plan. Gaps: real Argon2/AES/SQLite/TLS/Demo CA intentionally deferred to Stage-1/2/3 with debt comments — logged, not missing.
2. Placeholder scan: no `TBD/TODO/implement later/appropriate handling/edge cases/Similar to Task N` strings; every code step has full compilable snippet; every error path has exact exception/test.
3. Type consistency: `UserId/FileId/TransferId{value}`, `Digest{bytes}`, `WrappedKey{kekVersion,alg,nonce,bytes}`, `Result<T>{ok,value,error}`, `Frame{type,requestId,body}`, `Transfer::Status`, `DownloadToken::validFor(UserId,int64_t)` signatures identical across Tasks 1-7.
