#include <gtest/gtest.h>
#include "infrastructure/fake_hasher.hpp"
#include "infrastructure/argon2_hasher.hpp"
TEST(Hasher, FakeRoundTrip) {
  FakeHasher h;
  auto hash = h.hash("secret123");
  EXPECT_TRUE(h.verify(hash, "secret123"));
  EXPECT_FALSE(h.verify(hash, "wrong"));
}
TEST(Hasher, Argon2EncodesAndVerifies) {
  Argon2Hasher h;
  auto hash = h.hash("correct horse");
  EXPECT_NE(hash, "correct horse");
  EXPECT_EQ(hash.find("correct horse"), std::string::npos);
  EXPECT_TRUE(hash.rfind("$argon2id$", 0) == 0);
  EXPECT_TRUE(h.verify(hash, "correct horse"));
  EXPECT_FALSE(h.verify(hash, "wrong"));
}
TEST(Hasher, Argon2UniqueHashForSamePassword) {
  Argon2Hasher h;
  auto h1 = h.hash("same");
  auto h2 = h.hash("same");
  EXPECT_NE(h1, h2);
  EXPECT_TRUE(h.verify(h1, "same"));
  EXPECT_TRUE(h.verify(h2, "same"));
}
TEST(Hasher, Argon2EncodedContainsParams) {
  Argon2Hasher h;
  auto hash = h.hash("test");
  EXPECT_NE(hash.find("m=19456"), std::string::npos);
  EXPECT_NE(hash.find("t=2"), std::string::npos);
  EXPECT_NE(hash.find("p=1"), std::string::npos);
}
TEST(Hasher, NoPlaintextInHash) {
  Argon2Hasher h;
  auto hash = h.hash("SuperSecret123");
  EXPECT_EQ(hash.find("SuperSecret123"), std::string::npos);
}
