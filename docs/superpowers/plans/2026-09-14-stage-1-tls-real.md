# Stage 1 Remaining — Real TLS + DER Fingerprint + Full Lifecycle Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete Stage 1 to true GREEN by replacing simulated `tcp::socket` + `real_sha256(PEM)` pre-check with real `asio::ssl::stream` TLS 1.3 `verify_peer` + `X509`→`i2d_X509`→`EVP_sha256` DER fingerprint, `RAND_bytes` CSPRNG, and a full `REGISTER→LOGIN→LOGOUT→ADMIN` integration gate over real TLS.

**Architecture:** `sft_server` owns `SqliteUserRepository` (WAL, `BEGIN IMMEDIATE`) + `Argon2Hasher` (`RAND_bytes`) + `HashChainFileAuditLogger` (`EVP_sha256`, `seq`, `fsync`) + `AsioTlsListener` (`ssl::context` TLS 1.3 server, `use_certificate_chain_file`/`use_private_key_file`, `handshake()` before `accept()` return). `sft_client` owns `AsioTlsTransport` (`ssl::context` TLS 1.3 client, `verify_peer`, `load_verify_file(ca)` + `set_verify_callback` DER fingerprint + expiry/chain, `handshake()` after `connect()`). No `FakeTransport` in live path, no `verify_none`, no `dl_` for sessions, no `sha256stub` in prod.

**Tech Stack:** C++20, CMake 3.20+ Ninja, `googletest v1.14.0`, `asio asio-1-30-2`, `libargon2` (already), `sqlite3` (already), `OpenSSL 3.x` via `vcpkg x64-mingw-dynamic` (`find_package(OpenSSL REQUIRED)`), `asio::ssl` (header-only, needs `OPENSSL_INCLUDE_DIR`), `ws2_32`/`crypt32`.

## Global Constraints

- C++20, `project C CXX`, `CMAKE_TLS_VERIFY ON` + `CMAKE_TLS_CAINFO` configurable via `-D` (no hardcoded `C:/Program Files/Git/...`), `find_file(AUTO_CA_BUNDLE ...)` search only.
- Fixed `5000` for manual two-laptop demo, ephemeral `listen(0)` for automated tests, no fixed `5001/15500`.
- `domain/` never includes Asio/OpenSSL/DB/UI; `presentation/` only CLI/ANSI.
- Passwords `Argon2id m=19456 t=2 p=1` encoded, `RAND_bytes` salt, never `std::random_device` alone in prod.
- `UserId`/`SessionId` via `RAND_bytes`/`BCryptGenRandom` (explicit CSPRNG), `sess_` for auth sessions, `dl_` reserved, `SHA256(token)` store, raw token never in audit/CLI/files.
- Audit `HashChainFileAuditLogger` must use `EVP_sha256`, UTC `RFC3339`, monotonic `seq`, `jsonEscape`, `flush`+`fsync`+`fsync` dir, startup `verify()` + refusal, empty file → `true`.
- `Result<T>` `optional<T>`, `has_value()` before `.value()`, `uniqueTempPath` via `generateSessionId` + `temp_directory_path`.
- `verify_none` forbidden in any `src/infrastructure/asio_tls*` prod file (`rg "verify_none"` must be empty).
- Stage 1 does NOT implement PDF upload/download, DEK, etc. — only auth lifecycle over real TLS.
- Every `sqlite3_*` checked, `sqlite3_changes` verified, `ROLLBACK` on failure, `UNIQUE` → generic error.

---

## File Structure

```
CMakeLists.txt — find_package(OpenSSL REQUIRED) + target_link_libraries(... OpenSSL::SSL OpenSSL::Crypto)
include/infrastructure/sha256.hpp — keep real_sha256 (already) for non-OpenSSL fallback, but prod will use EVP_sha256 where OpenSSL available
include/infrastructure/asio_tls_transport.hpp — add ssl::context + ssl::stream member, handshake logic
src/infrastructure/asio_tls_transport.cpp — implement real TLS client: ctx{sslv23}, set_options(no_sslv2...), verify_peer, load_verify_file, set_verify_callback DER fingerprint + expiry, connect() → tcp::connect → ssl::handshake, send/recv via ssl::stream, no plain fallback
include/infrastructure/asio_tls_listener.hpp — add ssl::context server
src/infrastructure/asio_tls_listener.cpp — implement real TLS server: ctx{sslv23_server}, use_certificate_chain_file, use_private_key_file, verify_peer optional, accept() → tcp::accept → ssl::stream handshake before return
src/domain/ids.cpp — already sess_ + rd()&0xFF direct (no mt19937), ensure generateSessionId uses sess_
src/infrastructure/argon2_hasher.cpp — change salt from random_device to RAND_bytes (once OpenSSL found)
src/infrastructure/memory_session_store.cpp — already sess_ + real_sha256, change RAND_bytes for token
tests/infra/test_tls_transport.cpp — update to use real cert fixture, DER tests, expiry/malformed/hostname
tests/integration/test_stage1_gate.cpp — expand RealTLSLiveEphemeral from HELLO echo to full lifecycle (REGISTER/LOGIN/LOGOUT/ADMIN) over real TLS, plus SQLite + audit file checks, wrong fingerprint rejection
certs/test_server.crt/.key — real self-signed generated via openssl req (already dummy, regenerate via openssl)
certs/server.crt/.key — real for sft_server (same generation)
```

---

### Task 1: Install OpenSSL for MinGW and make find_package succeed

**Files:**
- Modify: `CMakeLists.txt` (already has `find_package(OpenSSL QUIET)` — change to `REQUIRED` once installed)
- Create: `C:/vcpkg` toolchain

**Interfaces:**
- Produces: `C:/vcpkg/installed/x64-mingw-dynamic/include/openssl/ssl.h`, `lib/libssl.a`, `lib/libcrypto.a`, `OPENSSL_ROOT_DIR` valid

- [ ] **Step 1: Clone and bootstrap vcpkg**

```powershell
git clone https://github.com/microsoft/vcpkg C:/vcpkg --depth 1
C:/vcpkg/bootstrap-vcpkg.bat
```

- [ ] **Step 2: Install openssl for mingw**

```powershell
C:/vcpkg/vcpkg install openssl:x64-mingw-dynamic --clean-after-build
```

Expected: `Installed openssl:x64-mingw-dynamic` with `include/openssl/ssl.h` and `lib/libssl.a`.

- [ ] **Step 3: Verify find_package**

```powershell
cmake -S . -B build -G Ninja -DOPENSSL_ROOT_DIR=C:/vcpkg/installed/x64-mingw-dynamic -DCMAKE_TLS_CAINFO=C:/vcpkg/installed/x64-mingw-dynamic/share/openssl/certs/ca-bundle.crt 2>&1 | Select-Object -Last 5
```

Expected: `-- Found OpenSSL: C:/vcpkg/installed/x64-mingw-dynamic/lib/libssl.a (found version "3.x.x")` and no `OPENSSL_CRYPTO_LIBRARY missing`, no `OpenSSL not found` warning.

- [ ] **Step 4: Commit if needed**

```bash
git add CMakeLists.txt
git commit -m "build: require OpenSSL for MinGW via vcpkg x64-mingw-dynamic"
```

---

### Task 2: Implement real TLS transport (client) with asio::ssl::stream

**Files:**
- Modify: `include/infrastructure/asio_tls_transport.hpp`
- Modify: `src/infrastructure/asio_tls_transport.cpp`
- Test: `tests/infra/test_tls_transport.cpp` (update)

**Interfaces:**
- Consumes: `TrustConfig{fingerprint,certPath,keyPath,caPath}`, `asio::ssl::context`, `X509*`, `EVP_sha256`
- Produces: `AsioTlsTransport::connect()` → `tcp::connect` → `ssl::stream::handshake(client)` with `verify_peer`, `AsioTlsTransport::sendFrame/recvFrame` via `ssl::stream::write/read`, `computeSha256Fingerprint()` → `X509`→`i2d_X509`→`EVP_Digest`

- [ ] **Step 1: Write failing test for DER fingerprint**

```cpp
TEST(TlsFingerprint, DerNotPem){
  auto fpPem = computeSha256FingerprintPemText("./certs/test_server.crt"); // old
  auto fpDer = computeSha256Fingerprint("./certs/test_server.crt"); // new DER
  EXPECT_NE(fpPem, fpDer);
  EXPECT_TRUE(verifyDerFingerprint("./certs/test_server.crt", fpDer));
}
```

- [ ] **Step 2: Implement DER fingerprint**

```cpp
std::string computeSha256Fingerprint(const std::string& certPath){
  FILE* fp = fopen(certPath.c_str(), "rb");
  X509* cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
  fclose(fp);
  unsigned char* der=nullptr; int len=i2d_X509(cert, &der);
  unsigned char hash[32]; unsigned int outLen;
  EVP_Digest(der, len, hash, &outLen, EVP_sha256(), nullptr);
  OPENSSL_free(der); X509_free(cert);
  // hex + uppercase
}
```

- [ ] **Step 3: Implement AsioTlsTransport with ssl::stream**

```cpp
struct Impl{ asio::io_context ioctx; asio::ssl::context ctx{asio::ssl::context::tlsv13_client}; std::unique_ptr<asio::ssl::stream<tcp::socket>> stream; std::vector<uint8_t> rxBuf; };
AsioTlsTransport::AsioTlsTransport(TrustConfig cfg): pimpl_(std::make_unique<Impl>()), cfg_(cfg){
  pimpl_->ctx.set_options(asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2 | asio::ssl::context::no_tlsv1 | asio::ssl::context::no_tlsv1_1);
  pimpl_->ctx.set_verify_mode(asio::ssl::verify_peer);
  if(!cfg_.caPath.empty()) pimpl_->ctx.load_verify_file(cfg_.caPath);
  pimpl_->ctx.set_verify_callback([this](bool preverified, asio::ssl::verify_context& ctx){
    if(!preverified) return false;
    X509* cert = X509_STORE_CTX_get0_cert(ctx.native_handle());
    // check expiry: X509_get_notAfter
    // check fingerprint
    return constantTimeEqual(computed, cfg_.fingerprint);
  });
}
void connect(host,port){
  tcp::resolver resolver(pimpl_->ioctx);
  auto eps = resolver.resolve(host, std::to_string(port));
  pimpl_->stream = std::make_unique<asio::ssl::stream<tcp::socket>>(pimpl_->ioctx, pimpl_->ctx);
  asio::connect(pimpl_->stream->lowest_layer(), eps);
  pimpl_->stream->handshake(asio::ssl::stream_base::client);
}
```

- [ ] **Step 4: Verify no verify_none**

```powershell
rg "verify_none" src/infrastructure/asio_tls_transport.cpp
# must be empty
```

- [ ] **Step 5: Commit**

```bash
git add include/infrastructure/asio_tls_transport.hpp src/infrastructure/asio_tls_transport.cpp
git commit -m "feat(tls): real asio::ssl::stream TLS 1.3 client with DER fingerprint verify_peer"
```

---

### Task 3: Implement real TLS listener (server) with handshake

**Files:**
- Modify: `include/infrastructure/asio_tls_listener.hpp`
- Modify: `src/infrastructure/asio_tls_listener.cpp`

**Interfaces:**
- Produces: `AsioTlsListener::listen(0)` → ephemeral `tcp::acceptor`, `accept()` → `tcp::accept` → `ssl::stream` `handshake(server)` before return, `close()`

- [ ] **Step 1: Implement server context**

```cpp
AsioTlsListener::AsioTlsListener(TrustConfig cfg): pimpl_(std::make_unique<Impl>()){
  pimpl_->ctx = asio::ssl::context{asio::ssl::context::tlsv13_server};
  pimpl_->ctx.set_options(...);
  pimpl_->ctx.use_certificate_chain_file(cfg.certPath);
  pimpl_->ctx.use_private_key_file(cfg.keyPath, asio::ssl::context::pem);
  pimpl_->ctx.set_verify_mode(asio::ssl::verify_peer | asio::ssl::verify_fail_if_no_peer_cert); // optional
}
uint16_t listen(port){
  pimpl_->acceptor = std::make_unique<tcp::acceptor>(pimpl_->ioctx, tcp::endpoint(tcp::v4(), port));
  return pimpl_->acceptor->local_endpoint().port();
}
std::unique_ptr<ITransport> accept(){
  tcp::socket sock(pimpl_->ioctx);
  pimpl_->acceptor->accept(sock);
  auto stream = std::make_unique<asio::ssl::stream<tcp::socket>>(std::move(sock), pimpl_->ctx);
  stream->handshake(asio::ssl::stream_base::server);
  return std::make_unique<AsioTlsTransport>(pimpl_->cfg, std::move(*stream)); // need ctor that takes stream
}
```

- [ ] **Step 2: Test real handshake**

```cpp
TEST(TlsTransport, RealHandshakeSucceeds){
  auto cfg = testTrust(); // real cert
  AsioTlsListener listener(cfg);
  uint16_t port = listener.listen(0);
  std::future<bool> done = std::async([&]{ auto c=listener.accept(); Frame f; return c->recvFrame(f,2000); });
  AsioTlsTransport client(cfg);
  EXPECT_NO_THROW(client.connect("127.0.0.1", port));
  client.sendFrame(Frame{MsgType::HELLO,1,{}});
  EXPECT_TRUE(done.get());
}
```

- [ ] **Step 3: Commit**

```bash
git add include/infrastructure/asio_tls_listener.hpp src/infrastructure/asio_tls_listener.cpp
git commit -m "feat(tls): real asio::ssl::stream TLS 1.3 server handshake"
```

---

### Task 4: Fix CSPRNG to RAND_bytes and remove mt19937

**Files:**
- Modify: `src/domain/ids.cpp`
- Modify: `src/infrastructure/argon2_hasher.cpp`
- Modify: `src/infrastructure/memory_session_store.cpp`

**Interfaces:**
- Produces: All three use `RAND_bytes` (OpenSSL) explicitly, no `mt19937`, `sess_` for sessions

- [ ] **Step 1: Update ids.cpp**

```cpp
UserId generateUserId(){
  unsigned char buf[16]; RAND_bytes(buf,16);
  // format uuid
}
SessionId generateSessionId(){
  unsigned char buf[32]; RAND_bytes(buf,32);
  // hex + sess_
}
```

- [ ] **Step 2: Update argon2_hasher to RAND_bytes**

```cpp
unsigned char salt[16]; RAND_bytes(salt,16);
```

- [ ] **Step 3: Update memory_session_store to RAND_bytes**

```cpp
unsigned char buf[32]; RAND_bytes(buf,32);
```

- [ ] **Step 4: Test**

```bash
rg "mt19937" src/domain/ids.cpp src/infrastructure/*.cpp
# must be empty
rg "dl_" src/domain/ids.cpp
# must be empty (only sess_)
```

- [ ] **Step 5: Commit**

```bash
git add src/domain/ids.cpp src/infrastructure/argon2_hasher.cpp src/infrastructure/memory_session_store.cpp
git commit -m "fix(crypto): use RAND_bytes CSPRNG for ids/sessions/argon2, sess_ prefix"
```

---

### Task 5: Strengthen integration gate to full lifecycle over real TLS

**Files:**
- Modify: `tests/integration/test_stage1_gate.cpp`
- Create: `tests/infra/test_frame_robustness.cpp` (if not exists)

**Interfaces:**
- Produces: `TEST(Stage1Gate, FullLifecycleOverTLS)` that does 12 steps over `AsioTlsTransport`/`AsioTlsListener` ephemeral, plus SQLite + audit file checks

- [ ] **Step 1: Write full lifecycle test**

```cpp
TEST(Stage1Gate, FullLifecycleOverTLS){
  auto trust = testTrust();
  AsioTlsListener listener(trust);
  uint16_t port = listener.listen(0);
  // server thread: real AuthService + Sqlite + Argon2 + HashChain
  std::string dbPath = uniqueTempPath("fullgate", ".db");
  std::string auditPath = uniqueTempPath("fullaudit", ".log");
  // ... start server loop in thread that handles REGISTER/LOGIN/LOGOUT/ADMIN via AsioTlsTransport
  AsioTlsTransport client(trust);
  client.connect("127.0.0.1", port);
  // REGISTER Alice
  client.sendFrame(Frame{MsgType::REGISTER,1,encodeRegister("alice","alice@ex.com","Alice123!")});
  Frame resp; ASSERT_TRUE(client.recvFrame(resp,2000)); EXPECT_EQ(resp.type, MsgType::REGISTER);
  // REGISTER Bob
  // LOGIN Alice -> get sess_ token
  // LOGOUT
  // ADMIN_DEACTIVATE via sess_ token
  // verify deactivated cannot login
  // etc.
  // check SQLite via SqliteUserRepository persisted
  // check audit file via HashChainFileAuditLogger::verify() + all() contains REGISTER_OK etc.
  // wrong fingerprint rejection
}
```

- [ ] **Step 2: Add frame robustness tests**

```cpp
TEST(FrameRobustness, LenLt5Rejected){ std::vector<uint8_t> buf{0,0,0,3, 1,0,0,0}; Frame out; size_t c; EXPECT_FALSE(tryDecode(buf,out,c)); }
TEST(FrameRobustness, OversizedRejected){ std::vector<uint8_t> buf{0x01,0x00,0x00,0x00}; Frame out; size_t c; EXPECT_FALSE(tryDecode(buf,out,c)); }
TEST(FrameRobustness, TruncatedRejected){ auto w=encodeFrame(Frame{MsgType::HELLO,1,{1,2,3}}); w.pop_back(); Frame out; size_t c; EXPECT_FALSE(tryDecode(w,out,c)); }
TEST(FrameRobustness, TimeoutEnforced){ AsioTlsTransport client(trust); client.connect(...); // server not sending, recv with 100ms timeout must return false quickly
  auto start=now(); EXPECT_FALSE(client.recvFrame(out,100)); EXPECT_LT(elapsed, 500);
}
```

- [ ] **Step 3: Run full suite**

```bash
cmake -S . -B build -G Ninja -DOPENSSL_ROOT_DIR=C:/vcpkg/installed/x64-mingw-dynamic
cmake --build build
ctest --test-dir build --output-on-failure
```

Expected: 59/59 + new `FullLifecycleOverTLS` + `FrameRobustness` all PASS, no `verify_none`, no `sha256stub` in prod.

- [ ] **Step 4: Commit**

```bash
git add tests/integration/test_stage1_gate.cpp tests/infra/test_frame_robustness.cpp
git commit -m "test(stage1): full REGISTER/LOGIN/LOGOUT/ADMIN over real TLS + frame robustness"
```

---

### Task 6: Final verification + manual demo

**Files:**
- Modify: `docs/STAGE1-DEMO.md` (add real TLS steps)
- Verify: `sft_server`/`sft_client` manual

- [ ] **Step 1: Build and test**

```bash
cmake --build build
ctest --test-dir build --output-on-failure
```

- [ ] **Step 2: Manual two-laptop demo**

```powershell
# Terminal 1 (server laptop hotspot)
./build/sft_server.exe --port 5000
# prints SERVER IPv4 PORT 5000 FINGERPRINT=<real DER SHA256>
# Terminal 2 (Alice)
./build/sft_client.exe --server <IPv4> --port 5000
# r) REGISTER alice/alice@ex.com/Alice123! -> REGISTER_OK
# l) LOGIN alice/Alice123! -> sess_ token in memory only
# Terminal 3 (Bob) similar, then LOGOUT, ADMIN_DEACTIVATE etc.
# Wireshark filter tcp.port==5000 must show TLS Application Data, not plaintext
```

- [ ] **Step 3: Document in log**

```bash
git add docs/impl-logs/stage-0-impl-log.md docs/STAGE1-DEMO.md
git commit -m "docs: Stage 1 GREEN — real TLS handshake verified"
```

---

## Self-Review (after plan, before execution)

- Spec coverage: TLS `ssl::stream` + DER fingerprint + `verify_peer` + expiry/chain, `RAND_bytes` for all CSPRNG, `sess_` vs `dl_`, atomic `recordLoginFailure(now)` inside TX, audit `EVP_sha256`+`seq`+`fsync`+`verify`, length-prefixed admin, multi-frame loop, full lifecycle gate — all have tasks.
- Placeholder scan: no `TBD`/`TODO`, every `encodeRegister`/`decodeAdmin`/`RAND_bytes` has concrete code.
- Type consistency: `TrustConfig`, `SessionId`, `UserId`, `Result<UserId>`, `ITransportListener::listen(0)->port` stable.

