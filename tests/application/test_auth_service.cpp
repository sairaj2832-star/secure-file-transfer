#include <gtest/gtest.h>
#include "application/auth_service.hpp"
#include "infrastructure/memory_user_repo.hpp"
#include "infrastructure/fake_hasher.hpp"
#include "infrastructure/vector_audit.hpp"
#include "infrastructure/memory_session_store.hpp"
#include "domain/clock.hpp"
TEST(AuthSvc, RegisterSuccessAndDuplicateGeneric) {
  MemoryUserRepository repo; FakeHasher hasher; VectorAudit audit; FakeClock clock(0); MemorySessionStore sessions(&clock);
  AuthService svc(&repo, &hasher, &sessions, &audit, &clock);
  auto r1 = svc.registerUser("alice", "alice@ex.com", "secret123");
  ASSERT_TRUE(r1.ok);
  ASSERT_TRUE(r1.value.has_value());
  auto r2 = svc.registerUser("alice", "other@ex.com", "secret123");
  EXPECT_FALSE(r2.ok);
  EXPECT_EQ(r2.error, "Registration failed");
  auto r3 = svc.registerUser("bob", "alice@ex.com", "secret123");
  EXPECT_FALSE(r3.ok);
  EXPECT_EQ(r3.error, "Registration failed");
  auto id = r1.value.value();
  EXPECT_EQ(repo.getEncodedHash(id).find("secret123"), std::string::npos);
}
TEST(AuthSvc, LoginSuccessAndGenericFailure) {
  MemoryUserRepository repo; FakeHasher hasher; VectorAudit audit; FakeClock clock(1000); MemorySessionStore sessions(&clock);
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
  MemoryUserRepository repo; FakeHasher hasher; VectorAudit audit; FakeClock clock(0); MemorySessionStore sessions(&clock);
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
  MemoryUserRepository repo; FakeHasher hasher; VectorAudit audit; FakeClock clock(0); MemorySessionStore sessions(&clock);
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
  MemoryUserRepository repo; FakeHasher hasher; VectorAudit audit; FakeClock clock(0); MemorySessionStore sessions(&clock);
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
  MemoryUserRepository repo; FakeHasher hasher; VectorAudit audit; FakeClock clock(0); MemorySessionStore sessions(&clock);
  AuthService svc(&repo, &hasher, &sessions, &audit, &clock);
  auto r = svc.registerUser("alice", "a@ex.com", "pw123456");
  ASSERT_TRUE(r.ok);
  static_assert(std::is_same_v<std::decay_t<decltype(r.value.value())>, UserId>);
}
