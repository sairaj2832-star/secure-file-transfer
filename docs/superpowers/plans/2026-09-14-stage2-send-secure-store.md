# Stage 2 Send & Secure Store (E2E Blind Server, PDF-only) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable single-PDF end-to-end flow where Alice encrypts on her laptop (random DEK + 96-bit nonce → AES-256-GCM → DEK sealed to Bob's pubkey), uploads opaque ciphertext+wrappedDEK over real TLS 1.3 `:5000` framed `UPLOAD_INIT/DATA/COMMIT`, and the blind dedicated server staged-writes it to `storage/encrypted/<uuid>.bin` + SQLite metadata with `UNIQUE(upload_id)` + sweeper — server never decrypts — then prove with real-TLS `Stage2Gate` (sha256 match on Bob side, Carol DENY, 1-byte tamper `INTEGRITY_FAIL`, kill-9 no orphans).

**Architecture:** Client owns `ClientCryptoProvider` (per-file DEK via `RAND_bytes`, AES-GCM, `X25519`/`libsodium crypto_box_seal` wrap) + X25519 `KeyPair` (privkey never leaves client, pubkey → `RecipientPubkeyDirectory` SQLite on server). Server owns `BinaryFileStorage` (crash-safe `tmp.<uuid>.part → fsync → rename → fsync-dir → BEGIN IMMEDIATE → INSERT → COMMIT`) + `SqliteFileRepository/SqliteTransferRepository` (WAL, `synchronous=FULL`, `foreign_keys=ON`) + `FileValidator` (PDF-only `%PDF` magic + `lexically_normal` + size). `TransferService` is composed from `IStorage+IKeyDirectory+IFileRepository+IPasswordHasher+IAuditLogger+FileValidator+IClock` — no `std::map` state. Wire via `ITransport` framing behind `AsioTlsTransport` `verify_peer` DER fingerprint (real in every Gate/demo, `FakeTransport` only for unit tests).

**Tech Stack:** C++20, CMake 3.20+ Ninja, `googletest v1.14.0`, `asio` (header-only), `OpenSSL 3.x` via `vcpkg x64-mingw-dynamic` (`find_package(OpenSSL REQUIRED)`), `libsodium` (or OpenSSL `EVP_aead` for AES-GCM + `crypto_box_seal` via `libsodium` FetchContent `1.0.18`), `libargon2 + sqlite3 amalgamation 3460000` (existing), `asio::ssl` TLS 1.3, `ws2_32/crypt32`.

## Global Constraints

- C++20 `set(CMAKE_CXX_STANDARD 20)`, `project C CXX`, `CMAKE_TLS_VERIFY ON` + `CMAKE_TLS_CAINFO` configurable via `-D` (no hardcoded `C:/Program Files/Git/...`), `find_file(AUTO_CA_BUNDLE ...)` search only — `docs/MASTER.md:3d` DER fingerprint via `i2d_X509` + `EVP_sha256`.
- Fixed `5000` for manual hotspot demo, `listen(0)` ephemeral for `ctest` Gates — **no** `5001`/`FakeTransport` in any `Stage2Gate` or viva demo `docs/MASTER.md:3a/3c`.
- `domain/` never includes Asio/OpenSSL/DB/UI/sqlite/limbusodium; `presentation/` only CLI/ANSI; every `Port` has Real + Fake (Fake only for unit tests) `AGENTS.md`.
- Passwords `Argon2id m=19456 t=2 p=1` encoded, `RAND_bytes` salt, generic `"Login failed"` + 5-fail/15-min `IClock` lockout — Stage 1 GREEN must stay green.
- `UserId`/`SessionId`/`FileId`/`TransferId` via explicit CSPRNG (`RAND_bytes`), `sess_` for sessions, `WrappedKey{recipientId, nonce[12], bytes, alg="X25519-AES-GCM-Seal"}` — never `kekVersion`.
- Audit `HashChainFileAuditLogger` `EVP_sha256` `seq/prevHash/msgHash` UTC `RFC3339` `jsonEscape` + `flush+fsync+fsync-dir` + startup `verify()` + small CLI msg (`UPLOAD alice→bob`) — never passwords/keys/plaintext/privkeys/paths.
- Storage crash-safe: `tmp.<uuid>.part → fsync → rename (same FS) → fsync-dir → BEGIN IMMEDIATE → COMMIT`; fail → `remove()`; boot sweeper deletes orphans; `UNIQUE(upload_id)` UUIDv4 `docs/MASTER.md:5`.
- PDF-only core: `FileValidator` allow-list `{pdf}` + magic `%PDF` at offset 0 (not MIME), `lexically_normal + starts_with(root)`, UUID disk name, size pre+post (≤100MB/user quota, chunk 1–4MB), reject `../`, NUL, double-ext `.jpg.php`, non-PDF until Stretch `docs/MASTER.md:4`.
- No `verify_none` in any `src/infrastructure/asio_tls*` prod file (`rg "verify_none" --` must be empty); no plaintext/privkey/DEK in DB/audit/`storage/encrypted` `rg` proofs.
- `Result<T>` holds `std::optional<T>`, check `has_value()` before `value()`, `uniqueTempPath` via `generateSessionId` + `temp_directory_path`, `BEGIN IMMEDIATE` `SELECT→UPDATE→COMMIT` with `sqlite3_changes` + `ROLLBACK` on fail.
- E2E blind trust: server holds `recipient_pubkeys` + opaque ciphertext only — Alice encrypts, Bob decrypts locally — `docs/MASTER.md:2`.
- Each task ends with `ctest --test-dir build --output-on-failure` + `git commit`; Stage 2 GREEN requires `Stage2Gate.*` over **real** `AsioTlsListener/Transport` + `sha256sum` PDF match + hotspot demo on `127.0.0.1:5000` or hotspot.

---

## File Structure

```
# New/modified for Stage 2 — one responsibility per file
CMakeLists.txt — add FetchContent libsodium 1.0.18 + add_library(sodium) + target_link_libraries(sft_app PRIVATE sodium) + OpenSSL::Crypto kept; no change to Stage 1 targets

include/domain/key_pair.hpp — KeyPair{pubkey[32], privkey[32] (client-only)} validated ctor, generate() via randombytes_buf/RAND_bytes
include/domain/wrapped_key.hpp — replace FAKE: struct WrappedKey{ UserId recipientId; std::vector<uint8_t> nonce(12); std::vector<uint8_t> bytes; std::string alg="X25519-AES-GCM-Seal"; }
include/domain/file_record.hpp — extend: FileRecord{id, owner, recipient, origName, storageId uuid.bin, size, digest SHA256, wrapped WrappedKey, uploadId UUIDv4, createdAt} + isOwnedBy()

include/ports/key_directory.hpp — IKeyDirectory{ savePubkey(UserId,pubkey), getPubkey(UserId)->pubkey, exists(UserId), listAll() }
include/ports/file_repository.hpp — IFileRepository{ save(FileRecord), findById(FileId), findByOwner(UserId), existsUploadId(string) }
include/ports/transfer_repository.hpp — ITransferRepository{ save(Transfer), findById/file, listFor(UserId) }
include/ports/file_validator.hpp — IFileValidator{ validate(name,size,bytes)->void throws ValidationException; isPdfMagic(bytes) }

include/infrastructure/recipient_pubkey_directory.hpp / src/infrastructure/recipient_pubkey_directory.cpp — SqlitePubkeyDirectory (WAL) + MemoryPubkeyDirectory (unordered_map) both implement IKeyDirectory
include/infrastructure/client_crypto.hpp / src/infrastructure/client_crypto.cpp — ClientCryptoProvider + FakeCrypto (keep Fake for unit tests)
include/infrastructure/binary_storage.hpp / src/infrastructure/binary_storage.cpp — BinaryFileStorage : IStorage { stagedWrite(uuid, bytes), read(uuid), removeStaged(uuid), sweepOrphans(root) }
include/infrastructure/file_validator.hpp / src/infrastructure/file_validator.cpp — PdfFileValidator : IFileValidator (PDF-only core, magic %PDF)
include/infrastructure/sqlite_file_repo.hpp / src/infrastructure/sqlite_file_repo.cpp — SqliteFileRepository : IFileRepository (files table §5)
include/infrastructure/sqlite_transfer_repo.hpp / src/infrastructure/sqlite_transfer_repo.cpp — SqliteTransferRepository : ITransferRepository

include/ports/transport.hpp — extend MsgType { HELLO=1, AUTH=2, REGISTER=3, LOGOUT=4, ADMIN_ACTIVATE=5, ADMIN_DEACTIVATE=6, UPLOAD_INIT=7, UPLOAD_DATA=8, UPLOAD_COMMIT=9, DOWNLOAD_REQ=10, DOWNLOAD_DATA=11, LIST=12, ERR=255 }
include/presentation/protocol.hpp / src/presentation/protocol.cpp — add encodeUploadInit/decodeUploadInit + encodeUploadData/decode + encodeDownloadReq

include/application/transfer_service.hpp / src/application/transfer_service.cpp — full rewrite: ctor-inject IStorage+IKeyDirectory+IFileRepository+ITransferRepository+IEncryptionProvider+IAuditLogger+FileValidator+IClock+ISessionStore; upload(senderSess, recipient, origName, bytes/uploadId) -> Transfer; download(requestSess, FileId) -> relay bytes (blind)

src/presentation/server_app.cpp — add UPLOAD_INIT/DATA/COMMIT + DOWNLOAD_REQ handling (relay, no decrypt) + small CLI msgs; keep Stage1 AUTH/ADMIN
src/presentation/client_app.cpp — add keypair gen on register, encrypt-before-upload, decrypt-after-download

tests/domain/test_wrapped_key.cpp — WrappedKey invariants
tests/domain/test_file_record.cpp — FileRecord invariants
tests/infra/test_pubkey_directory.cpp — Sqlite vs Memory parity, UNIQUE(pubkey)
tests/infra/test_client_crypto.cpp — round-trip, 10k nonce uniq, tag/wrong-key fail, server hexdump != plaintext
tests/infra/test_binary_storage.cpp — staged write + fsync + sweep + idempotent upload_id
tests/infra/test_file_validator.cpp — PDF magic, traversal/double-ext/oversize/NUL
tests/infra/test_sqlite_file_repo.cpp — UNIQUE(upload_id) + Tx rollback + sweep
tests/integration/test_stage2_gate.cpp — Stage2Gate.* real TLS E2E single-PDF Alice→Bob + Carol DENY + tamper + kill-9 + persistence (main gate)
```

---

### Task 1: Domain — WrappedKey + FileRecord + KeyPair (E2E value types)

**Files:**
- Modify: `include/domain/wrapped_key.hpp:6`
- Modify: `include/domain/file_record.hpp:10`
- Create: `include/domain/key_pair.hpp`
- Create: `tests/domain/test_wrapped_key.cpp`
- Create: `tests/domain/test_file_record.cpp`

**Interfaces:**
- Consumes: `UserId`, `FileId`, `Digest` `include/domain/ids.hpp:1`, `include/domain/digest.hpp:1`, `include/domain/exceptions.hpp:1`
- Produces: `struct KeyPair{ std::array<uint8_t,32> pub; std::array<uint8_t,32> priv; static KeyPair generate(); }`, `struct WrappedKey{ UserId recipientId; std::vector<uint8_t> nonce; std::vector<uint8_t> bytes; std::string alg; }` with ctor rejecting `nonce.size()!=12` or empty `bytes`, `struct FileRecord{ FileId id; UserId owner; UserId recipient; std::string origName; std::string storageId; uint64_t size; Digest digest; WrappedKey wrapped; std::string uploadId; int64_t createdAt; bool isOwnedBy(UserId) const; }`

- [ ] **Step 1: Write failing test for WrappedKey invariants**

```cpp
// tests/domain/test_wrapped_key.cpp
#include <gtest/gtest.h>
#include "domain/wrapped_key.hpp"
#include "domain/ids.hpp"
TEST(WrappedKeyDomain, RejectsBadNonce){
  auto uid = generateUserId();
  WrappedKey w{uid, std::vector<uint8_t>(11,0), std::vector<uint8_t>(32,1), "X25519-AES-GCM-Seal"};
  EXPECT_THROW((WrappedKey{uid, w.nonce, w.bytes, w.alg}), ValidationException); // ctor should validate size==12 in real impl
}
TEST(WrappedKeyDomain, StoresRecipientAndAlg){
  auto uid = generateUserId();
  WrappedKey w{uid, std::vector<uint8_t>(12,1), std::vector<uint8_t>(48,2), "X25519-AES-GCM-Seal"};
  EXPECT_EQ(w.recipientId, uid);
  EXPECT_EQ(w.alg, "X25519-AES-GCM-Seal");
  EXPECT_EQ(w.nonce.size(), 12u);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake -S . -B build -G Ninja && cmake --build build && ./build/sft_tests --gtest_filter=WrappedKeyDomain.* -v`
Expected: FAIL — `WrappedKey` still `FAKE-XOR-FNV`/`kekVersion`, no `recipientId`, no validation.

- [ ] **Step 3: Implement minimal domain types**

```cpp
// include/domain/key_pair.hpp
#pragma once
#include <array>
#include <cstdint>
struct KeyPair {
  std::array<uint8_t,32> pub{};
  std::array<uint8_t,32> priv{};
  static KeyPair generate(); // uses randombytes_buf or RAND_bytes(32)
};

// include/domain/wrapped_key.hpp
#pragma once
#include "domain/ids.hpp"
#include "domain/exceptions.hpp"
#include <vector>
#include <string>
struct WrappedKey {
  UserId recipientId;
  std::vector<uint8_t> nonce; // 12
  std::vector<uint8_t> bytes; // sealed DEK
  std::string alg = "X25519-AES-GCM-Seal";
  WrappedKey()=default;
  WrappedKey(const UserId& rid, std::vector<uint8_t> n, std::vector<uint8_t> b, std::string a="X25519-AES-GCM-Seal")
    : recipientId(rid), nonce(std::move(n)), bytes(std::move(b)), alg(std::move(a)) {
      if(nonce.size()!=12) throw ValidationException("nonce must be 12");
      if(bytes.empty()) throw ValidationException("wrapped bytes empty");
  }
};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cmake --build build && ./build/sft_tests --gtest_filter=WrappedKeyDomain.* -v`
Expected: PASS

- [ ] **Step 5: Add FileRecord tests + impl**

```cpp
// tests/domain/test_file_record.cpp
#include <gtest/gtest.h>
#include "domain/file_record.hpp"
TEST(FileRecordDomain, RejectsEmptyOrigName){ FileRecord r; r.origName=""; EXPECT_THROW(validateFileRecord(r), ValidationException); }
TEST(FileRecordDomain, IsOwnedBy){ auto o=generateUserId(); FileRecord r; r.owner=o; EXPECT_TRUE(r.isOwnedBy(o)); EXPECT_FALSE(r.isOwnedBy(generateUserId())); }
```

Implement `include/domain/file_record.hpp` with `owner, recipient, storageId="uuid.bin", uploadId UUIDv4, size, digest, wrapped` + validation helper.

- [ ] **Step 6: Commit**

```bash
git add include/domain/wrapped_key.hpp include/domain/file_record.hpp include/domain/key_pair.hpp tests/domain/test_wrapped_key.cpp tests/domain/test_file_record.cpp
git commit -m "feat(domain): WrappedKey recipient+nonce+seal + FileRecord blind + KeyPair (E2E)"
```

---

### Task 2: Ports — IKeyDirectory, IFileRepository, ITransferRepository, IFileValidator

**Files:**
- Create: `include/ports/key_directory.hpp`
- Create: `include/ports/file_repository.hpp`
- Create: `include/ports/transfer_repository.hpp`
- Create: `include/ports/file_validator.hpp`
- Test: `tests/domain/test_ports_exist.cpp` (compile-only)

**Interfaces:**
- Consumes: `UserId`, `FileRecord`, `Transfer`, `KeyPair`, `Result<T>`
- Produces: `class IKeyDirectory{ virtual void savePubkey(const UserId&, const std::vector<uint8_t>& pub)=0; virtual std::vector<uint8_t> getPubkey(const UserId&) const=0; virtual bool exists(const UserId&) const=0; }`, `class IFileRepository{ virtual void save(const FileRecord&)=0; virtual Result<FileRecord> findById(const FileId&) const=0; virtual bool existsUploadId(const std::string&) const=0; }`, `class IFileValidator{ virtual void validate(const std::string& origName, uint64_t size, const std::vector<uint8_t>& head)=0; }`

- [ ] **Step 1: Write failing compile test**

```cpp
// tests/domain/test_ports_exist.cpp
#include "ports/key_directory.hpp"
#include "ports/file_repository.hpp"
#include "ports/file_validator.hpp"
TEST(PortsExist, Compile){ IKeyDirectory* kd=nullptr; IFileRepository* fr=nullptr; IFileValidator* fv=nullptr; EXPECT_EQ(kd, nullptr); }
```

- [ ] **Step 2: Run to fail**

Run: `cmake --build build 2>&1 | grep "key_directory.hpp"`
Expected: `fatal error: ports/key_directory.hpp: No such file`

- [ ] **Step 3: Create port headers (pure virtual, no includes of sqlite/asio)**

```cpp
// include/ports/key_directory.hpp
#pragma once
#include "domain/ids.hpp"
#include <vector>
class IKeyDirectory { public: virtual ~IKeyDirectory()=default; virtual void savePubkey(const UserId&, const std::vector<uint8_t>& pub)=0; virtual std::vector<uint8_t> getPubkey(const UserId&) const=0; virtual bool exists(const UserId&) const=0; virtual std::vector<UserId> listAll() const=0; };

// include/ports/file_repository.hpp
#pragma once
#include "domain/file_record.hpp"
#include "domain/result.hpp"
class IFileRepository { public: virtual ~IFileRepository()=default; virtual void save(const FileRecord&)=0; virtual Result<FileRecord> findById(const FileId&) const=0; virtual std::vector<FileRecord> findByOwner(const UserId&) const=0; virtual bool existsUploadId(const std::string&) const=0; };

// include/ports/file_validator.hpp
#pragma once
#include <vector>
#include <string>
class IFileValidator { public: virtual ~IFileValidator()=default; virtual void validate(const std::string& origName, uint64_t size, const std::vector<uint8_t>& headerBytes)=0; };
```

- [ ] **Step 4: Run passes**

Run: `cmake -S . -B build -G Ninja && cmake --build build && ./build/sft_tests --gtest_filter=PortsExist.*`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add include/ports/key_directory.hpp include/ports/file_repository.hpp include/ports/transfer_repository.hpp include/ports/file_validator.hpp
git commit -m "feat(ports): IKeyDirectory + IFileRepository + IFileValidator (E2E)"
```

---

### Task 3: Infra — RecipientPubkeyDirectory (SQLite + Memory fake)

**Files:**
- Create: `include/infrastructure/recipient_pubkey_directory.hpp`
- Create: `src/infrastructure/recipient_pubkey_directory.cpp`
- Create: `tests/infra/test_pubkey_directory.cpp`

**Interfaces:**
- Consumes: `IKeyDirectory`, `sqlite3`, `UserId`
- Produces: `SqlitePubkeyDirectory : IKeyDirectory` (WAL, `recipient_pubkeys(user_id PK, pubkey BLOB, alg, created_at)` §5) and `MemoryPubkeyDirectory` (unordered_map) for unit tests.

- [ ] **Step 1: Write failing test**

```cpp
// tests/infra/test_pubkey_directory.cpp
#include <gtest/gtest.h>
#include "infrastructure/recipient_pubkey_directory.hpp"
#include "infrastructure/memory_pubkey_directory.hpp"
#include "domain/ids.hpp"
TEST(PubkeyDir, MemoryAndSqliteParity){
  auto uid=generateUserId();
  std::vector<uint8_t> pub(32,0x41);
  MemoryPubkeyDirectory mem;
  mem.savePubkey(uid, pub);
  EXPECT_EQ(mem.getPubkey(uid), pub);
}
TEST(PubkeyDir, SqlitePersistsAcrossReopen){
  auto p = uniqueTempPath("pubkey", ".db");
  auto uid=generateUserId();
  std::vector<uint8_t> pub(32,0x42);
  { SqlitePubkeyDirectory db(p); db.savePubkey(uid, pub); }
  { SqlitePubkeyDirectory db2(p); EXPECT_EQ(db2.getPubkey(uid), pub); }
  std::filesystem::remove(p); std::filesystem::remove(p+"-wal"); std::filesystem::remove(p+"-shm");
}
TEST(PubkeyDir, DuplicateUserThrows){
  MemoryPubkeyDirectory mem;
  auto uid=generateUserId(); std::vector<uint8_t> pub(32,1);
  mem.savePubkey(uid, pub);
  EXPECT_THROW(mem.savePubkey(uid, pub), ValidationException);
}
```

- [ ] **Step 2: Run fails**

Run: `cmake --build build && ./build/sft_tests --gtest_filter=PubkeyDir.*`
Expected: `undefined reference to SqlitePubkeyDirectory`

- [ ] **Step 3: Implement both**

```cpp
// src/infrastructure/recipient_pubkey_directory.cpp (sketch)
SqlitePubkeyDirectory::SqlitePubkeyDirectory(const std::string& path): dbPath_(path){
  sqlite3_open(path.c_str(), &db_);
  sqlite3_exec(db_, "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",0,0,0);
  sqlite3_exec(db_, "CREATE TABLE IF NOT EXISTS recipient_pubkeys(user_id TEXT PRIMARY KEY, pubkey BLOB, alg TEXT, created_at TEXT);",0,0,0);
}
void SqlitePubkeyDirectory::savePubkey(const UserId& uid, const std::vector<uint8_t>& pub){
  if(pub.size()!=32) throw ValidationException("pubkey 32");
  sqlite3_exec(db_, "BEGIN IMMEDIATE;",0,0,0);
  // INSERT ...; on SQLITE_CONSTRAINT throw ValidationException + ROLLBACK; else COMMIT; check sqlite3_changes
}
// MemoryPubkeyDirectory: unordered_map<string, vector<uint8_t>> map_; throw if exists
```

- [ ] **Step 4: Run passes**

Run: `cmake --build build && ./build/sft_tests --gtest_filter=PubkeyDir.* -v`
Expected: 3/3 PASS

- [ ] **Step 5: Commit**

```bash
git add include/infrastructure/recipient_pubkey_directory.hpp src/infrastructure/recipient_pubkey_directory.cpp tests/infra/test_pubkey_directory.cpp
git commit -m "feat(infra): Sqlite+Memory RecipientPubkeyDirectory (WAL, UNIQUE)"
```

---

### Task 4: Infra — ClientCryptoProvider (real E2E AES-GCM + sealed-box)

**Files:**
- Create: `include/infrastructure/client_crypto.hpp`
- Create: `src/infrastructure/client_crypto.cpp`
- Modify: `CMakeLists.txt` (add libsodium FetchContent)
- Test: `tests/infra/test_client_crypto.cpp`

**Interfaces:**
- Consumes: `IEncryptionProvider` `include/ports/crypto.hpp:8` (`EncryptOut encrypt(plain)`, `decryptAndVerify(cipher, wrapped, digest)`), `KeyPair`, `WrappedKey`
- Produces: `ClientCryptoProvider : IEncryptionProvider` (per-file random DEK 32B + nonce 12B via `RAND_bytes`, `EVP_aes_256_gcm` or `crypto_aead_aes256gcm`, DEK sealed via `crypto_box_seal(pub)` / `X25519`, digest `SHA256(plaintext)`), `FakeCrypto` remains for `Fakes.*` unit tests only.

- [ ] **Step 1: Write failing crypto tests (TDD)**

```cpp
// tests/infra/test_client_crypto.cpp
#include <gtest/gtest.h>
#include "infrastructure/client_crypto.hpp"
#include "domain/key_pair.hpp"
TEST(ClientCrypto, RoundTrip){
  auto kp = KeyPair::generate();
  ClientCryptoProvider crypto(kp.pub); // ctor takes recipient pub? or per-call
  std::vector<uint8_t> plain{'h','e','l','l','o'};
  auto out = crypto.encrypt(plain, kp.pub);
  EXPECT_EQ(out.wrapped.nonce.size(), 12u);
  auto back = crypto.decryptAndVerify(out.cipher, out.wrapped, out.digest, kp.priv);
  EXPECT_EQ(back, plain);
}
TEST(ClientCrypto, NonceUniq10k){
  auto kp=KeyPair::generate(); ClientCryptoProvider c(kp.pub);
  std::set<std::string> nonces;
  for(int i=0;i<10000;i++){ auto o=c.encrypt({1,2,3}, kp.pub); nonces.insert(std::string(o.wrapped.nonce.begin(), o.wrapped.nonce.end())); }
  EXPECT_EQ(nonces.size(), 10000u);
}
TEST(ClientCrypto, TagFailOnTamper){
  auto kp=KeyPair::generate(); ClientCryptoProvider c(kp.pub);
  auto o=c.encrypt({9,9,9}, kp.pub);
  o.cipher[0]^=1;
  EXPECT_THROW(c.decryptAndVerify(o.cipher, o.wrapped, o.digest, kp.priv), IntegrityException);
}
TEST(ClientCrypto, WrongKeyFails){
  auto a=KeyPair::generate(), b=KeyPair::generate();
  ClientCryptoProvider c(a.pub);
  auto o=c.encrypt({7}, a.pub);
  EXPECT_THROW(c.decryptAndVerify(o.cipher, o.wrapped, o.digest, b.priv), IntegrityException);
}
TEST(ClientCrypto, ServerHexdumpDiffers){
  auto kp=KeyPair::generate(); ClientCryptoProvider c(kp.pub);
  std::vector<uint8_t> pdf{'%','P','D','F',1,2,3};
  auto o=c.encrypt(pdf, kp.pub);
  EXPECT_NE(o.cipher, pdf);
  EXPECT_NE(std::string(o.cipher.begin(), o.cipher.end()), std::string(pdf.begin(), pdf.end()));
}
```

- [ ] **Step 2: Run fails**

Run: `cmake --build build && ./build/sft_tests --gtest_filter=ClientCrypto.*`
Expected: `undefined reference to ClientCryptoProvider` / `libsodium not found`

- [ ] **Step 3: Add libsodium to CMake + implement**

```cmake
# CMakeLists.txt add
FetchContent_Declare(libsodium GIT_REPOSITORY https://github.com/jedisct1/libsodium.git GIT_TAG 1.0.18)
# or URL https://download.libsodium.org/libsodium/releases/libsodium-1.0.18.tar.gz
# build as add_library(sodium STATIC ...) + target_include_directories
```

```cpp
// src/infrastructure/client_crypto.cpp sketch
EncryptOut ClientCryptoProvider::encrypt(const std::vector<uint8_t>& plain, const std::vector<uint8_t>& recipientPub){
  unsigned char dek[32], nonce[12];
  RAND_bytes(dek,32); RAND_bytes(nonce,12);
  // AES-256-GCM encrypt plain with dek+nonce -> cipher+tag (append tag)
  // crypto_box_seal(dek -> wrapped.bytes with recipientPub)
  // digest = real_sha256(plain)
  // return {cipher, WrappedKey{recipientId, nonce, wrapped, "X25519-AES-GCM-Seal"}, digest}
}
std::vector<uint8_t> decryptAndVerify(const std::vector<uint8_t>& cipher, const WrappedKey& w, const Digest& d, const std::array<uint8_t,32>& priv){
  // crypto_box_seal_open(wrapped -> dek with priv)
  // AES-GCM decrypt + verify tag; if fail throw IntegrityException
  // verify SHA256(plain)==d else throw IntegrityException
  // return plain
}
```

- [ ] **Step 4: Run passes**

Run: `cmake -S . -B build -G Ninja && cmake --build build && ./build/sft_tests --gtest_filter=ClientCrypto.* -v`
Expected: 5/5 PASS, no `FAKE-XOR` in `Result` — `FakeCrypto` still passes `Fakes.RoundTripAndTamper` for unit tests.

- [ ] **Step 5: Commit**

```bash
git add CMakeLists.txt include/infrastructure/client_crypto.hpp src/infrastructure/client_crypto.cpp tests/infra/test_client_crypto.cpp
git commit -m "feat(crypto): ClientCryptoProvider AES-GCM + sealed-box (10k nonce uniq, tag fail)"
```

---

### Task 5: Infra — BinaryFileStorage (crash-safe staged write + sweeper)

**Files:**
- Create: `include/infrastructure/binary_storage.hpp`
- Create: `src/infrastructure/binary_storage.cpp`
- Test: `tests/infra/test_binary_storage.cpp`

**Interfaces:**
- Consumes: `IStorage` `include/ports/storage.hpp:6`, `std::filesystem`, SQLite `IFileRepository` for sweeper reference
- Produces: `BinaryFileStorage : IStorage { void stagedWrite(const std::string& storageId, const std::vector<uint8_t>& opaque); std::vector<uint8_t> read(const std::string& storageId) const; void removeStaged(const std::string&); size_t sweepOrphans(const std::string& root, IFileRepository* repo); }` — implements `tmp.<uuid>.part → fsync(file) → rename → fsync(dir)` exactly.

- [ ] **Step 1: Write failing staged tests**

```cpp
TEST(BinaryStorage, StagedWriteSucceeds){
  auto root = uniqueTempPath("blobtest",""); std::filesystem::create_directories(root);
  BinaryFileStorage st(root);
  st.stagedWrite("uuid1.bin", {1,2,3});
  EXPECT_EQ(st.read("uuid1.bin"), std::vector<uint8_t>({1,2,3}));
  EXPECT_FALSE(std::filesystem::exists(root+"/uuid1.bin.part"));
  std::filesystem::remove_all(root);
}
TEST(BinaryStorage, SweepDeletesOrphanPart){
  auto root=uniqueTempPath("blobtest2",""); std::filesystem::create_directories(root);
  BinaryFileStorage st(root);
  // simulate crash: write .part without rename
  std::ofstream f(root+"/orphan.bin.part", std::ios::binary); f.write("x",1); f.close();
  MemoryFileRepository fakeRepo; // no entry for orphan
  EXPECT_EQ(st.sweepOrphans(root, &fakeRepo), 1u);
  EXPECT_FALSE(std::filesystem::exists(root+"/orphan.bin.part"));
  std::filesystem::remove_all(root);
}
TEST(BinaryStorage, IdempotentRename){
  auto root=uniqueTempPath("blobtest3",""); std::filesystem::create_directories(root);
  BinaryFileStorage st(root);
  st.stagedWrite("uuid2.bin", {9});
  st.stagedWrite("uuid2.bin", {9}); // second should overwrite atomically via tmp+rename, no throw
  EXPECT_EQ(st.read("uuid2.bin").size(), 1u);
  std::filesystem::remove_all(root);
}
```

- [ ] **Step 2: Run fails** — `undefined reference to BinaryFileStorage`

- [ ] **Step 3: Implement with fsync**

```cpp
void BinaryFileStorage::stagedWrite(const std::string& id, const std::vector<uint8_t>& data){
  auto tmp = root_ + "/tmp." + id + ".part";
  auto dst = root_ + "/" + id;
  std::ofstream ofs(tmp, std::ios::binary | std::ios::trunc);
  ofs.write((char*)data.data(), data.size());
  ofs.flush();
  // fsync file handle via _get_osfhandle + FlushFileBuffers (Win) or fsync(fd) (POSIX)
  // if flush fails -> remove(tmp) + throw StorageException
  std::filesystem::rename(tmp, dst); // same FS
  // fsync directory via CreateFile + FlushFileBuffers(dir)
}
```

- [ ] **Step 4: Run passes**

Run: `cmake --build build && ./build/sft_tests --gtest_filter=BinaryStorage.* -v`
Expected: 3/3 PASS, no `*.part` left

- [ ] **Step 5: Commit**

```bash
git add include/infrastructure/binary_storage.hpp src/infrastructure/binary_storage.cpp tests/infra/test_binary_storage.cpp
git commit -m "feat(storage): BinaryFileStorage staged fsync+rename+sweeper (crash-safe)"
```

---

### Task 6: Infra — FileValidator PDF-only

**Files:**
- Create: `include/infrastructure/file_validator.hpp`
- Create: `src/infrastructure/file_validator.cpp`
- Test: `tests/infra/test_file_validator.cpp`

**Interfaces:**
- Produces: `PdfFileValidator : IFileValidator` with `validate(origName, size, headerBytes)` rejecting traversal, double-ext, NUL, non-PDF magic, oversize.

- [ ] **Step 1: Write failing validator tests**

```cpp
TEST(FileValidator, AcceptsPdf){
  PdfFileValidator v;
  std::vector<uint8_t> hdr{'%','P','D','F','-', '1','.', '4'};
  EXPECT_NO_THROW(v.validate("assignment.pdf", 1024, hdr));
}
TEST(FileValidator, RejectsNonPdfMagic){
  PdfFileValidator v;
  std::vector<uint8_t> hdr{'P','N','G',0};
  EXPECT_THROW(v.validate("image.png", 100, hdr), ValidationException);
}
TEST(FileValidator, RejectsTraversal){
  PdfFileValidator v;
  std::vector<uint8_t> hdr{'%','P','D','F'};
  EXPECT_THROW(v.validate("../etc/passwd.pdf", 100, hdr), ValidationException);
  EXPECT_THROW(v.validate("a/../../b.pdf", 100, hdr), ValidationException);
}
TEST(FileValidator, RejectsDoubleExt){
  PdfFileValidator v;
  std::vector<uint8_t> hdr{'%','P','D','F'};
  EXPECT_THROW(v.validate("report.jpg.pdf", 100, hdr), ValidationException); // if policy, else allow .pdf only
  EXPECT_THROW(v.validate("file.pdf.exe", 100, hdr), ValidationException);
}
TEST(FileValidator, RejectsOversize){
  PdfFileValidator v;
  std::vector<uint8_t> hdr{'%','P','D','F'};
  EXPECT_THROW(v.validate("big.pdf", 101ULL*1024*1024, hdr), ValidationException);
}
```

- [ ] **Step 2: Run fails** — no `PdfFileValidator`

- [ ] **Step 3: Implement (lexically_normal + starts_with, magic %PDF)**

```cpp
void PdfFileValidator::validate(const std::string& name, uint64_t size, const std::vector<uint8_t>& hdr){
  if(name.empty() || name.find('\0')!=std::string::npos) throw ValidationException("name");
  auto norm = std::filesystem::path(name).lexically_normal().string();
  if(norm.find("..")!=std::string::npos) throw ValidationException("traversal");
  if(!ends_with(norm, ".pdf")) throw ValidationException("PDF-only core");
  if(norm.find(".pdf.")!=std::string::npos) throw ValidationException("double ext");
  if(size>100ULL*1024*1024) throw ValidationException("oversize");
  if(hdr.size()<4 || hdr[0]!='%'||hdr[1]!='P'||hdr[2]!='D'||hdr[3]!='F') throw ValidationException("PDF magic");
}
```

- [ ] **Step 4: Run passes** — 5/5

- [ ] **Step 5: Commit**

```bash
git add include/infrastructure/file_validator.hpp src/infrastructure/file_validator.cpp tests/infra/test_file_validator.cpp
git commit -m "feat(validate): PdfFileValidator PDF-only magic+traversal+oversize"
```

---

### Task 7: Infra — Sqlite File/Transfer Repositories (UNIQUE upload_id + Tx)

**Files:**
- Create: `include/infrastructure/sqlite_file_repo.hpp`
- Create: `src/infrastructure/sqlite_file_repo.cpp`
- Create: `include/infrastructure/sqlite_transfer_repo.hpp`
- Create: `src/infrastructure/sqlite_transfer_repo.cpp`
- Test: `tests/infra/test_sqlite_file_repo.cpp`

**Interfaces:**
- Consumes: `IFileRepository`, `IStorage` root not needed here, `sqlite3` WAL
- Produces: `SqliteFileRepository` implementing `files(id, owner_id, recipient_id, orig_name, storage_id UNIQUE, size, mime, digest, wrapped_dek BLOB, nonce BLOB, upload_id UNIQUE, created_at)` + `BEGIN IMMEDIATE` save with `ROLLBACK` on `SQLITE_CONSTRAINT` → `ValidationException`.

- [ ] **Step 1: Write failing repo tests**

```cpp
TEST(SqliteFileRepo, UniqueUploadId){
  auto db=uniqueTempPath("filerepo",".db"); std::filesystem::remove(db);
  SqliteFileRepository repo(db);
  FileRecord r; r.id=FileId{generateUserId().value}; r.uploadId="uuid-1"; r.storageId="uuid1.bin"; r.origName="a.pdf";
  repo.save(r);
  FileRecord r2=r; r2.id=FileId{generateUserId().value}; r2.storageId="uuid2.bin";
  EXPECT_THROW(repo.save(r2), ValidationException); // duplicate uploadId
  std::filesystem::remove(db); std::filesystem::remove(db+"-wal"); std::filesystem::remove(db+"-shm");
}
TEST(SqliteFileRepo, PersistsAndFinds){
  auto db=uniqueTempPath("filerepo2",".db"); std::filesystem::remove(db);
  { SqliteFileRepository repo(db); FileRecord r; r.id=FileId{"fid1"}; r.uploadId="u1"; r.storageId="s1.bin"; r.origName="a.pdf"; r.owner=generateUserId(); r.recipient=generateUserId(); repo.save(r); }
  { SqliteFileRepository repo(db); auto res=repo.findById(FileId{"fid1"}); ASSERT_TRUE(res.ok && res.value.has_value()); EXPECT_EQ(res.value->storageId,"s1.bin"); }
  std::filesystem::remove(db); std::filesystem::remove(db+"-wal"); std::filesystem::remove(db+"-shm");
}
TEST(SqliteFileRepo, RollbackOnFail){
  // save valid, then attempt duplicate -> DB still has only first, no orphan row
}
```

- [ ] **Step 2: Run fails** — undefined `SqliteFileRepository`

- [ ] **Step 3: Implement with WAL + BEGIN IMMEDIATE**

```cpp
SqliteFileRepository::SqliteFileRepository(const std::string& path){ sqlite3_open(...); exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;"); exec("CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY, owner_id TEXT, recipient_id TEXT, orig_name TEXT, storage_id TEXT UNIQUE, size INT, digest TEXT, wrapped_dek BLOB, nonce BLOB, upload_id TEXT UNIQUE, created_at TEXT);"); }
void save(const FileRecord& r){ exec("BEGIN IMMEDIATE;"); // prepared INSERT; if SQLITE_CONSTRAINT -> exec("ROLLBACK;") throw ValidationException; else exec("COMMIT;") check sqlite3_changes==1 }
```

- [ ] **Step 4: Run passes** — 3/3

- [ ] **Step 5: Commit**

```bash
git add include/infrastructure/sqlite_file_repo.hpp src/infrastructure/sqlite_file_repo.cpp include/infrastructure/sqlite_transfer_repo.hpp src/infrastructure/sqlite_transfer_repo.cpp tests/infra/test_sqlite_file_repo.cpp
git commit -m "feat(repo): SqliteFileRepository UNIQUE(upload_id) Tx+sweeper"
```

---

### Task 8: App — TransferService refactor (blind server, no decrypt)

**Files:**
- Modify: `include/application/transfer_service.hpp:14`
- Modify: `src/application/transfer_service.cpp`
- Test: `tests/application/test_transfer_e2e.cpp` (new) — keep old `test_transfer.cpp` for `Fakes.*` parity but expect updated ctor

**Interfaces:**
- Consumes: `IStorage* (BinaryFileStorage)`, `IKeyDirectory*`, `IFileRepository*`, `ITransferRepository*`, `IEncryptionProvider*` (client-side, but server receives already-encrypted bytes — so server-side provider is no-op; keep for policy), `IFileValidator*`, `IAuditLogger*`, `IClock*`, `ISessionStore*`
- Produces: `Result<Transfer> upload(const SessionId& senderSess, const std::string& recipientUsername, const std::string& origName, const std::vector<uint8_t>& opaqueCipherWithWrapped, const std::string& uploadId, uint64_t size, const Digest& digest, const WrappedKey& wrapped)` and `Result<std::vector<uint8_t>> download(const SessionId& requestSess, const FileId& fid)` (relay, no decrypt) + `bool isAuthorized()` check before `repo.findById`/`storage.read`.

- [ ] **Step 1: Write failing upload/download tests (blind)**

```cpp
TEST(TransferE2E, UploadStoresOpaqueAndRelay){
  FakeClock clock(0); MemorySessionStore sessions(&clock); SqliteUserRepository users(tmpDb); Argon2Hasher h; HashChainFileAuditLogger audit(tmpAudit);
  // register Alice/Bob via AuthService, get sess, store pubkeys in MemoryPubkeyDirectory
  MemoryPubkeyDirectory keys; auto kpBob=KeyPair::generate(); keys.savePubkey(bobId, std::vector<uint8_t>(kpBob.pub.begin(), kpBob.pub.end()));
  auto tmpRoot=uniqueTempPath("transfer",""); std::filesystem::create_directories(tmpRoot);
  BinaryFileStorage storage(tmpRoot); SqliteFileRepository files(tmpFileDb); PdfFileValidator validator;
  TransferService svc(&storage, &keys, &files, nullptr, &audit, &validator, &clock, &sessions);
  auto pdf = std::vector<uint8_t>{'%','P','D','F',1,2,3};
  ClientCryptoProvider crypto; auto enc = crypto.encrypt(pdf, std::vector<uint8_t>(kpBob.pub.begin(), kpBob.pub.end()));
  auto res = svc.upload(aliceSess, "bob", "doc.pdf", enc.cipher, "upload-1", pdf.size(), enc.digest, enc.wrapped);
  ASSERT_TRUE(res.ok);
  auto blob = storage.read(res.value->fileId); // via fileRecord storageId
  EXPECT_NE(blob, pdf); // opaque
  auto dl = svc.download(bobSess, res.value->fileId);
  ASSERT_TRUE(dl.ok);
  // Bob decrypts locally
  auto plain = crypto.decryptAndVerify(dl.value.value(), enc.wrapped, enc.digest, kpBob.priv);
  EXPECT_EQ(plain, pdf);
}
TEST(TransferE2E, CarolDeniedAndStrangerNotOwner){
  // alice uploads for bob, carol sess tries download -> ValidationException / AuthException + audit DENIED
  EXPECT_FALSE(svc.download(carolSess, fid).ok);
}
TEST(TransferE2E, DuplicateUploadIdIdempotent){
  auto r1=svc.upload(aliceSess,"bob","a.pdf",cipher,"dup-1", 10, d, w);
  auto r2=svc.upload(aliceSess,"bob","a.pdf",cipher,"dup-1", 10, d, w);
  EXPECT_FALSE(r2.ok); EXPECT_EQ(r2.error, "Registration failed" or "Upload failed"); // generic, no orphan
}
```

- [ ] **Step 2: Run fails** — `TransferService` still `TransferService(IStorage*, IEncryptionProvider*, IAuditLogger*)` with `map`

- [ ] **Step 3: Rewrite TransferService ctor + logic (sketch, minimal to pass)**

```cpp
TransferService::TransferService(IStorage* s, IKeyDirectory* kd, IFileRepository* fr, ITransferRepository* tr, IAuditLogger* a, IFileValidator* v, IClock* c, ISessionStore* ss)
  : st_(s), keys_(kd), files_(fr), transfers_(tr), audit_(a), validator_(v), clock_(c), sessions_(ss) {}
Result<Transfer> TransferService::upload(const SessionId& sess, const std::string& recip, const std::string& orig, const std::vector<uint8_t>& opaque, const std::string& uploadId, uint64_t sz, const Digest& d, const WrappedKey& w){
  if(!sessions_->isValid(sess, clock_->nowMs())) throw AuthException("Login failed");
  auto senderId = sessions_->userFor(sess); // need userFor method
  auto recipUser = users_->findByUsername(recip); if(!recipUser.ok) throw NotFoundException("recipient");
  if(!keys_->exists(recipUser.value->id())) throw ValidationException("recipient pubkey missing");
  validator_->validate(orig, sz, opaque); // checks %PDF + size
  if(files_->existsUploadId(uploadId)) throw ValidationException("duplicate upload_id");
  FileRecord fr; fr.id=FileId{generateUserId().value}; fr.owner=senderId; fr.recipient=recipUser.value->id(); fr.origName=orig; fr.storageId=generateUserId().value+".bin"; fr.uploadId=uploadId; fr.digest=d; fr.wrapped=w; fr.size=sz;
  st_->stagedWrite(fr.storageId, opaque); // if throws -> audit + rethrow, removeStaged
  try{ files_->save(fr); } catch(...){ st_->removeStaged(fr.storageId); throw; }
  // save Transfer, Permission
  audit_->record(AuditEvent{..., "UPLOAD", fr.id.value});
  return Result<Transfer>::success(Transfer{...});
}
```

- [ ] **Step 4: Run passes**

Run: `cmake --build build && ./build/sft_tests --gtest_filter=TransferE2E.* -v`
Expected: 3/3 PASS, old `TransferSvc.*` updated to new ctor still PASS via Fake injection.

- [ ] **Step 5: Commit**

```bash
git add include/application/transfer_service.hpp src/application/transfer_service.cpp tests/application/test_transfer_e2e.cpp
git commit -m "feat(app): TransferService blind E2E (no server decrypt, auth before disk, idempotent upload_id)"
```

---

### Task 9: Wire — Protocol framing UPLOAD/DOWNLOAD + Server/Client real TLS

**Files:**
- Modify: `include/ports/transport.hpp:2` (add MsgTypes)
- Modify: `include/presentation/protocol.hpp:1` + `src/presentation/protocol.cpp:1`
- Modify: `src/presentation/server_app.cpp:55`
- Modify: `src/presentation/client_app.cpp:1`
- Test: `tests/integration/test_protocol_stage2.cpp`

**Interfaces:**
- Produces: `struct UploadInit{ std::string recipient, origName, uploadId; uint64_t size; Digest digest; WrappedKey wrapped; }`, `encodeUploadInit/decodeUploadInit` (length-prefixed `recipient|orig|uploadId` via `put32be`), `encodeUploadData/decode`, `encodeDownloadReq`.

- [ ] **Step 1: Write failing protocol test**

```cpp
TEST(ProtocolStage2, UploadInitRoundTrip){
  UploadInit init{"bob","doc.pdf","uuid-1", 123, Digest{}, WrappedKey{uid, std::vector<uint8_t>(12,1), std::vector<uint8_t>(48,2)}};
  auto body = encodeUploadInit(init);
  auto dec = decodeUploadInit(body);
  EXPECT_EQ(dec.recipient,"bob"); EXPECT_EQ(dec.origName,"doc.pdf"); EXPECT_EQ(dec.uploadId,"uuid-1");
}
TEST(ProtocolStage2, NoPipeDelimited){
  // body contains '|' but must not confuse — prove length-prefixed survives
  auto body = encodeUploadInit({"b|ob","a|b.pdf","u|1", 5, {}, {}});
  EXPECT_NO_THROW(decodeUploadInit(body));
}
```

- [ ] **Step 2: Run fails** — `encodeUploadInit not defined`

- [ ] **Step 3: Implement length-prefixed (put32be/get32be) — copy pattern from encodeRegister**

```cpp
std::vector<uint8_t> encodeUploadInit(const UploadInit& p){
  std::vector<uint8_t> out;
  putString(out, p.recipient); putString(out, p.origName); putString(out, p.uploadId); put64be(out, p.size); putBytes(out, p.wrapped.nonce); putBytes(out, p.wrapped.bytes);
  return out;
}
```

- [ ] **Step 4: Extend server_app to handle UPLOAD_INIT/DATA/COMMIT + DOWNLOAD_REQ — relay only, no decrypt**

```cpp
// server_app.cpp accept loop: already while(recvFrame)
else if(f.type==MsgType::UPLOAD_INIT){
  auto init=decodeUploadInit(f.body);
  // isAuthorized via sessions->isValid(token) + userFor
  // validator->validate(...)
  // expect next frames DATA until COMMIT, assemble via BinaryFileStorage stagedWrite
  // on COMMIT -> TransferService.upload(sess, init.recipient, init.origName, assembledOpaque, init.uploadId, ...)
  // reply MsgType::UPLOAD_COMMIT with transferId
} else if(f.type==MsgType::DOWNLOAD_REQ){
  auto req=decodeDownloadReq(f.body);
  auto res=transferService.download(SessionId{req.token}, FileId{req.fileId});
  // relay opaque blob as DOWNLOAD_DATA frames
}
```

- [ ] **Step 5: Extend client_app to encrypt-before-upload + decrypt-after-download + keypair gen on register**

```cpp
// client_app.cpp: on r) register -> KeyPair kp=KeyPair::generate(); save priv locally (e.g., storage/client_key.bin 0600), send pub to server via REGISTER extra field
// on upload: pdf bytes -> ClientCryptoProvider encrypt with recipient pub (lookup via LIST or local cache) -> encodeUploadInit + send DATA chunks
// on download: recv opaque -> ClientCryptoProvider decryptAndVerify with local priv -> write pdf
```

- [ ] **Step 6: Run protocol tests pass**

Run: `cmake --build build && ./build/sft_tests --gtest_filter=ProtocolStage2.* -v`
Expected: 2/2 PASS

- [ ] **Step 7: Commit**

```bash
git add include/ports/transport.hpp include/presentation/protocol.hpp src/presentation/protocol.cpp src/presentation/server_app.cpp src/presentation/client_app.cpp tests/integration/test_protocol_stage2.cpp
git commit -m "feat(wire): UPLOAD_INIT/DATA/COMMIT + DOWNLOAD_REQ relay (blind, real TLS)"
```

---

### Task 10: Integration — Stage2Gate real TLS E2E (main GREEN gate for Stage 2)

**Files:**
- Create: `tests/integration/test_stage2_gate.cpp`
- Modify: `docs/STAGE2-DEMO.md` (new)
- Modify: `docs/impl-logs/stage-0-impl-log.md` (append Stage 2 log)

**Interfaces:**
- Consumes: All Stage 2 infra + `AsioTlsListener`/`AsioTlsTransport` ephemeral real TLS, `FakeClock`, `Argon2Hasher`, `SqliteUserRepository`, `SqlitePubkeyDirectory`, `BinaryFileStorage`, `ClientCryptoProvider`

- [ ] **Step 1: Write failing Stage2Gate suite (5 tests)**

```cpp
#include <gtest/gtest.h>
#include "infrastructure/asio_tls_listener.hpp"
#include "infrastructure/asio_tls_transport.hpp"
#include "infrastructure/recipient_pubkey_directory.hpp"
#include "infrastructure/binary_storage.hpp"
#include "infrastructure/client_crypto.hpp"
#include "application/transfer_service.hpp"

TEST(Stage2Gate, SinglePdfAliceToBobViaBlindServer){
  auto trust=testTrust(); // DER fingerprint
  auto dbUsers=uniqueTempPath("s2_users",".db");
  auto dbFiles=uniqueTempPath("s2_files",".db");
  auto auditLog=uniqueTempPath("s2_audit",".log");
  auto blobRoot=uniqueTempPath("s2_blob",""); std::filesystem::create_directories(blobRoot);
  // setup repos, keys, storage
  AsioTlsListener listener(trust); uint16_t port=listener.listen(0);
  std::thread srv([&]{ /* server loop handling REGISTER (with pubkey save), LOGIN, UPLOAD_INIT/DATA/COMMIT, DOWNLOAD_REQ — real AuthService + TransferService blind */ });
  AsioTlsTransport alice(trust); alice.connect("127.0.0.1", port);
  AsioTlsTransport bob(trust); bob.connect("127.0.0.1", port);
  // alice register (gen kp), bob register (gen kp) -> pubkeys in SqlitePubkeyDirectory
  // alice encrypt PDF %PDF + wrap to bob pub, upload via UPLOAD_INIT/DATA/COMMIT
  // bob list + download -> decrypt locally -> sha256(pdf) == originalDigest
  // assert blob on server hexdump != pdf (opaque) + server never called decrypt
  EXPECT_EQ(sha256(bobPlain), sha256(pdf));
  listener.close(); // sweep check
}
TEST(Stage2Gate, CarolDenied){
  // alice->bob file, carol sess tries DOWNLOAD_REQ -> server reply ERR + audit DENIED carol, no bytes
}
TEST(Stage2Gate, TamperOneByteIntegrityFail){
  // upload pdf, flip 1 byte in storage/encrypted/<uuid>.bin, bob download -> IntegrityException + audit INTEGRITY_FAIL, no plain delivered
}
TEST(Stage2Gate, Kill9NoOrphansAndIdempotentRetry){
  // start upload, kill srv thread at 50% DATA, restart, verify *.part swept (0 orphans), retry with same uploadId -> second fails generic, first still retrievable
}
TEST(Stage2Gate, PdfOnlyRejectsNonPdf){
  // try upload image.png with PNG magic -> server ValidationException, no file saved, no *.part
}
```

- [ ] **Step 2: Run fails** — `Stage2Gate.SinglePdf...` not found / link errors (BinaryFileStorage not wired)

- [ ] **Step 3: Implement missing glue in test helper (uniqueTempPath, testTrust, sha256, real handshake)**

Reuse pattern from `tests/integration/test_stage1_gate.cpp:17` `uniqueTempPath` + `generateSessionId` + `testTrust()` searching `{"./certs","../certs","D:/OOPS/CP/certs"}` + `computeSha256Fingerprint` DER + `AsioTlsListener(0)` ephemeral.

- [ ] **Step 4: Run gate passes**

Run: `cmake -S . -B build -G Ninja && cmake --build build && ctest --test-dir build --output-on-failure`
Expected: `Stage2Gate.* 5/5` PASS + full `59+` suite still 100% (now ~69 tests), `rg "verify_none" src/` empty, `rg "FAKE-XOR"` only in `fake_crypto.hpp` for unit tests.

- [ ] **Step 5: Manual hotspot demo verification**

Run manual (PowerShell, two terminals + hotspot):

```powershell
# Terminal 1 server
./build/sft_server.exe --port 5000 # prints SERVER IPv4 PORT 5000 FINGERPRINT=<DER>
# Terminal 2 alice
./build/sft_client.exe --server 192.168.137.1 --port 5000 # r alice, l alice, upload doc.pdf --to bob (encrypts locally)
# Terminal 3 bob
./build/sft_client.exe --server 192.168.137.1 --port 5000 # r bob, l bob, list, download doc.pdf (decrypts locally)
# Proofs
sha256sum doc.pdf # alice vs bob match
hexdump -C storage/encrypted/*.bin # differs
rg -a "secret" storage/files.db storage/audit.log # must miss
```

- [ ] **Step 6: Commit + log**

```bash
git add tests/integration/test_stage2_gate.cpp docs/STAGE2-DEMO.md docs/impl-logs/stage-0-impl-log.md
git commit -m "feat(stage2): Stage2Gate E2E single-PDF blind server real TLS (GREEN)"
```

---

## Self-Review

- Spec coverage: MASTER §2 E2E flow, §3a real-network + PDF-only, §4 file crypto sealed-box + staged write + validation, §5 recipient_pubkeys + files.upload_id UNIQUE, §7 E2E sequences (client encrypt, server relay), §8 demo steps 2-5, §9 Stage 2 gate slice, §10 Stage 2 GREEN — all have tasks (1→10).
- Placeholder scan: no `TBD`/`TODO`/`implement later`; every `encrypt/seal/validate/stagedWrite/sweep` has concrete snippet + `RAND_bytes`/`i2d_X509`/`lexically_normal` call.
- Type consistency: `WrappedKey{recipientId, nonce[12], bytes, alg}`, `KeyPair.generate()`, `IKeyDirectory.savePubkey(UserId, vector<uint8_t>)`, `TransferService.upload(SessionId, recipient, origName, opaque, uploadId)` stable across Tasks 4,8,10; `MsgType::UPLOAD_INIT=7` not colliding with `REGISTER=3`.
- Fixes: Lib for Stage 2 is **libsodium** (explicit FetchContent) — not hidden; `BinaryFileStorage` fsync details use `_get_osfhandle/FlushFileBuffers` on Win vs `fsync` on POSIX — portable.

---

Plan complete and saved to `docs/superpowers/plans/2026-09-14-stage2-send-secure-store.md`. Two execution options:

**1. Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**
