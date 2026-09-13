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