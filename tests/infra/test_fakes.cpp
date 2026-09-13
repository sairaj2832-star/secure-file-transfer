// tests/infra/test_fakes.cpp
#include <gtest/gtest.h>
#include "infrastructure/fake_crypto.hpp"
#include "infrastructure/memory_storage.hpp"
#include "domain/exceptions.hpp"
TEST(Fakes, RoundTripAndTamper) {
  FakeCrypto c;
  std::vector<uint8_t> plain{'h','i'};
  auto out = c.encrypt(plain);
  EXPECT_EQ(c.decryptAndVerify(out.cipher, out.wrapped, out.digest), plain);
  out.cipher[0] ^= 0x01;
  EXPECT_THROW(c.decryptAndVerify(out.cipher, out.wrapped, out.digest), IntegrityException);
}
TEST(Fakes, StorageWriteRead) {
  MemoryStorage s; s.write("k", {1,2,3});
  EXPECT_EQ(s.read("k"), (std::vector<uint8_t>{1,2,3}));
}