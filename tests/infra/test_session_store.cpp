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
  auto tok = ss.createForUser(UserId{"alice"}, 0);
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
  EXPECT_EQ(t1.value.rfind("sess_", 0), 0u);
}
TEST(SessionStore, RevokedFieldModel) {
  Session s{SessionId{"sess_test"}, UserId{"u1"}, 1000, 5000, false};
  EXPECT_TRUE(s.isValid(2000));
  s.revoked = true;
  EXPECT_FALSE(s.isValid(2000));
}
