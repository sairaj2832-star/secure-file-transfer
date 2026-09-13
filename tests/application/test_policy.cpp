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