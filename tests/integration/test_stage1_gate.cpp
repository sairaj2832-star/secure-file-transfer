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
#include <fstream>
namespace fs = std::filesystem;
static std::string uniqueTempPath(const std::string& prefix, const std::string& ext){
  return (fs::temp_directory_path() / (prefix + "_" + generateSessionId().value + ext)).string();
}
static TrustConfig testTrust(){
  TrustConfig c;
  // try repo root then build dir
  for(auto p : {"./certs/test_server.crt", "../certs/test_server.crt", "D:/OOPS/CP/certs/test_server.crt"}){
    if(std::filesystem::exists(p)){ c.certPath=p; c.keyPath= std::string(p).substr(0, std::string(p).find("test_server.crt"))+"test_server.key"; c.caPath=p; break; }
  }
  if(c.certPath.empty()) c.certPath="./certs/test_server.crt";
  c.fingerprint = computeSha256Fingerprint(c.certPath);
  return c;
}
static std::string readFile(const std::string& p){
  std::ifstream f(p, std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}
TEST(Stage1Gate, AliceBobRegisterLoginLogout) {
  auto dbPath = uniqueTempPath("stage1_gate", ".db");
  auto auditPath = uniqueTempPath("stage1_audit", ".log");
  fs::remove(dbPath); fs::remove(auditPath);
  {
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
    {
      SqliteUserRepository repo2(dbPath);
      auto ga = repo2.findByUsername("alice");
      ASSERT_TRUE(ga.ok && ga.value.has_value());
      auto gb = repo2.findByUsername("bob");
      ASSERT_TRUE(gb.ok && gb.value.has_value());
    }
  }
  fs::remove(dbPath); fs::remove(auditPath);
  fs::remove(dbPath+"-wal"); fs::remove(dbPath+"-shm");
}
TEST(Stage1Gate, AdminDeactivateBlocksLogin) {
  auto dbPath = uniqueTempPath("stage1_gate2", ".db");
  auto auditPath = uniqueTempPath("stage1_audit2", ".log");
  fs::remove(dbPath); fs::remove(auditPath);
  {
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
  }
  fs::remove(dbPath); fs::remove(auditPath);
  fs::remove(dbPath+"-wal"); fs::remove(dbPath+"-shm");
}
TEST(Stage1Gate, NonAdminCannotDeactivate) {
  auto uniqueAudit = uniqueTempPath("stage1_nonadmin", ".log");
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
  {
    SqliteUserRepository repo(dbPath); Argon2Hasher hasher; FakeClock clock(0);
    HashChainFileAuditLogger audit(auditPath); MemorySessionStore sessions(&clock);
    AuthService auth(&repo,&hasher,&sessions,&audit,&clock);
    auth.registerUser("alice","a@ex.com","SuperSecret123");
    auth.login("alice","wrong");
    std::string auditRaw = readFile(auditPath);
    EXPECT_EQ(auditRaw.find("SuperSecret123"), std::string::npos);
    std::string dbRaw = readFile(dbPath);
    EXPECT_EQ(dbRaw.find("SuperSecret123"), std::string::npos);
    auto aliceFound3 = repo.findByUsername("alice");
    ASSERT_TRUE(aliceFound3.ok && aliceFound3.value.has_value());
    auto aliceId = aliceFound3.value->id();
    EXPECT_NE(repo.getEncodedHash(aliceId).find("$argon2id$"), std::string::npos);
  }
  fs::remove(dbPath); fs::remove(auditPath);
  fs::remove(dbPath+"-wal"); fs::remove(dbPath+"-shm");
}
TEST(Stage1Gate, RealTLSLiveEphemeral) {
  auto trust = testTrust();
  if(!fs::exists(trust.certPath)) FAIL() << "test cert missing — generate via certs/README.md";
  AsioTlsListener listener(trust);
  uint16_t port = listener.listen(0);
  ASSERT_NE(port, 0);
  std::promise<bool> serverGot;
  std::thread srv([&]{
    try{
      auto conn = listener.accept();
      Frame f; if(conn->recvFrame(f, 5000)){
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
  auto badTrust = trust; badTrust.fingerprint = std::string(64,'0');
  AsioTlsListener listener2(trust);
  uint16_t port2 = listener2.listen(0);
  std::thread srv2([&]{ try{ auto c=listener2.accept(); Frame f; c->recvFrame(f,1000);}catch(...){} });
  AsioTlsTransport badClient(badTrust);
  EXPECT_THROW(badClient.connect("127.0.0.1", port2), TransportException);
  if(srv2.joinable()) { srv2.detach(); }
  listener2.close();
}
