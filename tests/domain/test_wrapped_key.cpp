#include <gtest/gtest.h>
#include "domain/wrapped_key.hpp"
#include "domain/ids.hpp"
#include "domain/exceptions.hpp"

TEST(WrappedKeyDomain, RejectsBadNonce) {
  auto uid = generateUserId();
  std::vector<uint8_t> badNonce(11, 0);
  std::vector<uint8_t> goodBytes(32, 1);
  // ctor should validate nonce size ==12
  EXPECT_THROW((WrappedKey{uid, badNonce, goodBytes, "X25519-AES-GCM-Seal"}), ValidationException);
  // also empty bytes should throw
  EXPECT_THROW((WrappedKey{uid, std::vector<uint8_t>(12, 1), std::vector<uint8_t>{}, "X25519-AES-GCM-Seal"}), ValidationException);
}

TEST(WrappedKeyDomain, StoresRecipientAndAlg) {
  auto uid = generateUserId();
  WrappedKey w{uid, std::vector<uint8_t>(12, 1), std::vector<uint8_t>(48, 2), "X25519-AES-GCM-Seal"};
  EXPECT_EQ(w.recipientId, uid);
  EXPECT_EQ(w.alg, "X25519-AES-GCM-Seal");
  EXPECT_EQ(w.nonce.size(), 12u);
  EXPECT_EQ(w.bytes.size(), 48u);
}

TEST(WrappedKeyDomain, RejectsEmptyBytes) {
  auto uid = generateUserId();
  EXPECT_THROW((WrappedKey{uid, std::vector<uint8_t>(12, 0), std::vector<uint8_t>{}, "X25519-AES-GCM-Seal"}), ValidationException);
}
