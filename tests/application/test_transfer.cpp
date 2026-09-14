// tests/application/test_transfer.cpp — updated for blind TransferService
#include <gtest/gtest.h>
#include "application/transfer_service.hpp"
#include "infrastructure/memory_storage.hpp"
#include "infrastructure/memory_file_repo.hpp"
#include "infrastructure/memory_pubkey_directory.hpp"
#include "infrastructure/memory_user_repo.hpp"
#include "infrastructure/memory_session_store.hpp"
#include "infrastructure/file_validator.hpp"
#include "infrastructure/vector_audit.hpp"
#include "domain/clock.hpp"
#include "domain/key_pair.hpp"

TEST(TransferSvc, AliceBobCarolFlow) {
  FakeClock clock(0);
  MemorySessionStore sessions(&clock);
  MemoryUserRepository users;
  MemoryPubkeyDirectory keys;
  MemoryFileRepository files;
  MemoryStorage st;
  VectorAudit au;
  PdfFileValidator validator;

  // create users
  UserId aliceId = generateUserId();
  UserId bobId = generateUserId();
  UserId carolId = generateUserId();
  User alice(aliceId, "alice", "alice@ex.com");
  User bob(bobId, "bob", "bob@ex.com");
  User carol(carolId, "carol", "carol@ex.com");
  users.save(alice, "hash1");
  users.save(bob, "hash2");
  users.save(carol, "hash3");

  SessionId aliceSess = sessions.createForUser(aliceId, clock.nowMs());
  SessionId bobSess = sessions.createForUser(bobId, clock.nowMs());
  SessionId carolSess = sessions.createForUser(carolId, clock.nowMs());

  std::vector<uint8_t> dummyPub(32, 0x11);
  keys.savePubkey(aliceId, dummyPub);
  keys.savePubkey(bobId, dummyPub);
  keys.savePubkey(carolId, dummyPub);

  TransferService svc(&st, &keys, &files, nullptr, &au, &validator, &clock, &sessions, &users);

  std::vector<uint8_t> pdf{'%', 'P', 'D', 'F', 'h', 'i'};
  WrappedKey w{bobId, std::vector<uint8_t>(12, 0x02), std::vector<uint8_t>(32, 0x03)};
  Digest d{};

  auto up = svc.upload(aliceSess, "bob", "a.pdf", pdf, "upload-1", pdf.size(), d, w);
  ASSERT_TRUE(up.ok && up.value.has_value());

  auto bobBytes = svc.download(bobSess, up.value->file);
  ASSERT_TRUE(bobBytes.ok && bobBytes.value.has_value());
  EXPECT_EQ(bobBytes.value.value(), pdf);

  auto carolRes = svc.download(carolSess, up.value->file);
  EXPECT_FALSE(carolRes.ok);
}
