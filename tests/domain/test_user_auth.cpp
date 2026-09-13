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
  User u(generateUserId(), "alice", "a@ex.com");
  (void)u.username(); (void)u.email(); (void)u.role();
}
