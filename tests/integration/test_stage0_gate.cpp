// tests/integration/test_stage0_gate.cpp — updated for blind TransferService (no server decrypt)
#include <gtest/gtest.h>
#include "application/transfer_service.hpp"
#include "infrastructure/memory_storage.hpp"
#include "infrastructure/memory_file_repo.hpp"
#include "infrastructure/memory_pubkey_directory.hpp"
#include "infrastructure/memory_user_repo.hpp"
#include "infrastructure/memory_session_store.hpp"
#include "infrastructure/file_validator.hpp"
#include "infrastructure/vector_audit.hpp"
#include "infrastructure/client_crypto.hpp"
#include "domain/clock.hpp"
#include "domain/key_pair.hpp"

TEST(Stage0Gate, AliceBobCarolTamper) {
  FakeClock clock(0);
  MemorySessionStore sessions(&clock);
  MemoryUserRepository users;
  MemoryPubkeyDirectory keys;
  MemoryFileRepository files;
  MemoryStorage st;
  VectorAudit au;
  PdfFileValidator validator;

  UserId aliceId = generateUserId();
  UserId bobId = generateUserId();
  UserId carolId = generateUserId();
  users.save(User(aliceId, "alice", "alice@ex.com"), "h1");
  users.save(User(bobId, "bob", "bob@ex.com"), "h2");
  users.save(User(carolId, "carol", "carol@ex.com"), "h3");
  SessionId aliceSess = sessions.createForUser(aliceId, clock.nowMs());
  SessionId bobSess = sessions.createForUser(bobId, clock.nowMs());
  SessionId carolSess = sessions.createForUser(carolId, clock.nowMs());
  std::vector<uint8_t> dummyPub(32, 0x33);
  keys.savePubkey(bobId, dummyPub);
  keys.savePubkey(aliceId, dummyPub);
  keys.savePubkey(carolId, dummyPub);

  TransferService svc(&st, &keys, &files, nullptr, &au, &validator, &clock, &sessions, &users);

  // Bob's real keypair for E2E (but for this gate use dummy wrap + pdf)
  std::vector<uint8_t> pdf{'%', 'P', 'D', 'F', 10, 20, 30};
  auto kpBob = KeyPair::generate();
  // overwrite dummy with real pub for bob
  // re-save not allowed duplicate, so we need fresh directory — use new keys for this test
  // Instead create new directory with real pub
  MemoryPubkeyDirectory keys2;
  keys2.savePubkey(aliceId, dummyPub);
  keys2.savePubkey(bobId, std::vector<uint8_t>(kpBob.pub.begin(), kpBob.pub.end()));
  keys2.savePubkey(carolId, dummyPub);
  TransferService svc2(&st, &keys2, &files, nullptr, &au, &validator, &clock, &sessions, &users);

  ClientCryptoProvider crypto;
  auto enc = crypto.encrypt(pdf, std::vector<uint8_t>(kpBob.pub.begin(), kpBob.pub.end()));
  enc.wrapped.recipientId = bobId;

  auto up = svc2.upload(aliceSess, "bob", "report.pdf", enc.cipher, "stage0-upload-1", pdf.size(), enc.digest, enc.wrapped);
  ASSERT_TRUE(up.ok && up.value.has_value());
  EXPECT_TRUE(svc2.download(bobSess, up.value->file).ok);
  EXPECT_FALSE(svc2.download(carolSess, up.value->file).ok);

  // tamper 1 byte in store — blind server will still relay, but client decrypt must fail
  auto frRes = files.findById(up.value->file);
  ASSERT_TRUE(frRes.ok && frRes.value.has_value());
  auto blob = st.read(frRes.value->storageId);
  blob[0] ^= 0x01;
  st.write(frRes.value->storageId, blob);

  auto tampered = svc2.download(bobSess, up.value->file);
  ASSERT_TRUE(tampered.ok && tampered.value.has_value());
  // client-side integrity check should fail
  EXPECT_THROW(crypto.decryptAndVerify(tampered.value.value(), enc.wrapped, enc.digest, kpBob.priv), IntegrityException);

  auto log = au.all();
  bool sawDeny = false;
  for (auto& e : log) if (e.action == "DENIED") sawDeny = true;
  EXPECT_TRUE(sawDeny);
  // No server INTEGRITY_FAIL in blind mode — tamper detected client side
}
