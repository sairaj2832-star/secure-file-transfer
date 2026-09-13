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
  repo.save(User(adminId, "admin", "admin@ex.com", "admin", "active"), "$argon2id$h");
  repo.save(User(aliceId, "alice", "alice@ex.com", "user", "inactive"), "$argon2id$h");
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
