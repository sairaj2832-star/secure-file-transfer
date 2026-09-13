// tests/application/test_transfer.cpp
#include <gtest/gtest.h>
#include "application/transfer_service.hpp"
#include "infrastructure/fake_crypto.hpp"
#include "infrastructure/memory_storage.hpp"
#include "infrastructure/vector_audit.hpp"
TEST(TransferSvc, AliceBobCarolFlow) {
  MemoryStorage st; FakeCrypto cr; VectorAudit au;
  TransferService svc(&st, &cr, &au);
  svc.addUser("alice"); svc.addUser("bob"); svc.addUser("carol");
  auto up = svc.upload(UserId{"alice"}, "bob", "a.pdf", {'h','i'});
  ASSERT_TRUE(up.ok && up.value.has_value());
  auto bobBytes = svc.download(UserId{"bob"}, up.value->file);
  ASSERT_TRUE(bobBytes.ok && bobBytes.value.has_value());
  EXPECT_EQ(bobBytes.value.value(), (std::vector<uint8_t>{'h','i'}));
  auto carol = svc.download(UserId{"carol"}, up.value->file);
  EXPECT_FALSE(carol.ok);
}