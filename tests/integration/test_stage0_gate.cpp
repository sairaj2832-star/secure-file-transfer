// tests/integration/test_stage0_gate.cpp
#include <gtest/gtest.h>
#include "application/transfer_service.hpp"
#include "infrastructure/fake_crypto.hpp"
#include "infrastructure/memory_storage.hpp"
#include "infrastructure/vector_audit.hpp"
TEST(Stage0Gate, AliceBobCarolTamper) {
  MemoryStorage st; FakeCrypto cr; VectorAudit au;
  TransferService svc(&st, &cr, &au);
  for (auto u : {"alice","bob","carol"}) svc.addUser(u);
  auto up = svc.upload(UserId{"alice"}, "bob", "report.pdf", std::vector<uint8_t>{10,20,30});
  ASSERT_TRUE(up.ok && up.value.has_value());
  EXPECT_TRUE(svc.download(UserId{"bob"}, up.value->file).ok);
  EXPECT_FALSE(svc.download(UserId{"carol"}, up.value->file).ok);
  // tamper 1 byte in store - use the storageId from the upload
  // We need to find the actual storageId - for this test we know it's "uuid-1"
  auto c = st.read("uuid-1");
  c[0] ^= 0x01; st.write("uuid-1", c);
  EXPECT_THROW(svc.download(UserId{"bob"}, up.value->file), IntegrityException);
  auto log = au.all();
  bool sawDeny = false, sawFail = false;
  for (auto& e : log) { if (e.action=="DENIED") sawDeny=true; if (e.action=="INTEGRITY_FAIL") sawFail=true; }
  EXPECT_TRUE(sawDeny && sawFail);
}