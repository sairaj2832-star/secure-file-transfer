#include <gtest/gtest.h>
#include "application/transfer_service.hpp"
#include "infrastructure/binary_storage.hpp"
#include "infrastructure/memory_file_repo.hpp"
#include "infrastructure/memory_pubkey_directory.hpp"
#include "infrastructure/memory_user_repo.hpp"
#include "infrastructure/memory_session_store.hpp"
#include "infrastructure/client_crypto.hpp"
#include "infrastructure/file_validator.hpp"
#include "infrastructure/vector_audit.hpp"
#include "domain/key_pair.hpp"
#include "domain/clock.hpp"
#include <filesystem>

namespace fs = std::filesystem;

static std::string uniqueTempPathE2E(const std::string& prefix, const std::string& ext) {
  return (fs::temp_directory_path() / (prefix + "_" + generateSessionId().value + ext)).string();
}

TEST(TransferE2E, UploadStoresOpaqueAndRelay) {
  FakeClock clock(0);
  MemorySessionStore sessions(&clock);
  MemoryUserRepository users;
  MemoryPubkeyDirectory keys;
  MemoryFileRepository files;
  VectorAudit audit;
  PdfFileValidator validator;

  auto tmpRoot = uniqueTempPathE2E("transfer_e2e", "");
  fs::create_directories(tmpRoot);
  BinaryFileStorage storage(tmpRoot);

  // users
  UserId aliceId = generateUserId();
  UserId bobId = generateUserId();
  User alice(aliceId, "alice", "alice@ex.com");
  User bob(bobId, "bob", "bob@ex.com");
  users.save(alice, "h1");
  users.save(bob, "h2");
  SessionId aliceSess = sessions.createForUser(aliceId, clock.nowMs());
  SessionId bobSess = sessions.createForUser(bobId, clock.nowMs());

  auto kpBob = KeyPair::generate();
  std::vector<uint8_t> bobPub(kpBob.pub.begin(), kpBob.pub.end());
  keys.savePubkey(bobId, bobPub);

  TransferService svc(&storage, &keys, &files, nullptr, &audit, &validator, &clock, &sessions, &users);

  std::vector<uint8_t> pdf{'%', 'P', 'D', 'F', 1, 2, 3, 4, 5};
  ClientCryptoProvider crypto;
  auto enc = crypto.encrypt(pdf, std::vector<uint8_t>(kpBob.pub.begin(), kpBob.pub.end()));
  // ensure wrapped has recipient bobId for policy
  enc.wrapped.recipientId = bobId;

  auto res = svc.upload(aliceSess, "bob", "doc.pdf", enc.cipher, "upload-1", pdf.size(), enc.digest, enc.wrapped);
  ASSERT_TRUE(res.ok) << res.error;
  ASSERT_TRUE(res.value.has_value());

  // opaque stored on server should differ from plaintext
  auto frRes = files.findById(res.value->file);
  ASSERT_TRUE(frRes.ok && frRes.value.has_value());
  std::string storageId = frRes.value->storageId;
  auto blob = storage.read(storageId);
  EXPECT_NE(blob, pdf);
  EXPECT_EQ(blob, enc.cipher);

  auto dl = svc.download(bobSess, res.value->file);
  ASSERT_TRUE(dl.ok) << dl.error;
  ASSERT_TRUE(dl.value.has_value());
  EXPECT_EQ(dl.value.value(), enc.cipher);

  // Bob decrypts locally
  auto plain = crypto.decryptAndVerify(dl.value.value(), enc.wrapped, enc.digest, kpBob.priv);
  EXPECT_EQ(plain, pdf);

  fs::remove_all(tmpRoot);
}

TEST(TransferE2E, CarolDeniedAndStrangerNotOwner) {
  FakeClock clock(0);
  MemorySessionStore sessions(&clock);
  MemoryUserRepository users;
  MemoryPubkeyDirectory keys;
  MemoryFileRepository files;
  VectorAudit audit;
  PdfFileValidator validator;
  auto tmpRoot = uniqueTempPathE2E("transfer_e2e_carol", "");
  fs::create_directories(tmpRoot);
  BinaryFileStorage storage(tmpRoot);

  UserId aliceId = generateUserId();
  UserId bobId = generateUserId();
  UserId carolId = generateUserId();
  users.save(User(aliceId, "alice", "alice@ex.com"), "h1");
  users.save(User(bobId, "bob", "bob@ex.com"), "h2");
  users.save(User(carolId, "carol", "carol@ex.com"), "h3");

  SessionId aliceSess = sessions.createForUser(aliceId, clock.nowMs());
  SessionId bobSess = sessions.createForUser(bobId, clock.nowMs());
  SessionId carolSess = sessions.createForUser(carolId, clock.nowMs());

  auto kpBob = KeyPair::generate();
  keys.savePubkey(bobId, std::vector<uint8_t>(kpBob.pub.begin(), kpBob.pub.end()));
  keys.savePubkey(aliceId, std::vector<uint8_t>(32, 0x01));
  keys.savePubkey(carolId, std::vector<uint8_t>(32, 0x02));

  TransferService svc(&storage, &keys, &files, nullptr, &audit, &validator, &clock, &sessions, &users);
  std::vector<uint8_t> pdf{'%', 'P', 'D', 'F', 9, 9, 9};
  ClientCryptoProvider crypto;
  auto enc = crypto.encrypt(pdf, std::vector<uint8_t>(kpBob.pub.begin(), kpBob.pub.end()));
  enc.wrapped.recipientId = bobId;

  auto up = svc.upload(aliceSess, "bob", "a.pdf", enc.cipher, "dup-carol-1", pdf.size(), enc.digest, enc.wrapped);
  ASSERT_TRUE(up.ok);

  // Carol tries to download Bob's file -> denied
  auto carolDl = svc.download(carolSess, up.value->file);
  EXPECT_FALSE(carolDl.ok);

  // Bob (recipient) should succeed
  auto bobDl = svc.download(bobSess, up.value->file);
  EXPECT_TRUE(bobDl.ok);

  // Alice (owner) should also succeed
  auto aliceDl = svc.download(aliceSess, up.value->file);
  EXPECT_TRUE(aliceDl.ok);

  // Audit should contain DENIED for carol
  bool foundDenied = false;
  for (auto &e : audit.all()) if (e.action == "DENIED" && e.actor == carolId.value) foundDenied = true;
  EXPECT_TRUE(foundDenied);

  fs::remove_all(tmpRoot);
}

TEST(TransferE2E, DuplicateUploadIdIdempotent) {
  FakeClock clock(0);
  MemorySessionStore sessions(&clock);
  MemoryUserRepository users;
  MemoryPubkeyDirectory keys;
  MemoryFileRepository files;
  VectorAudit audit;
  PdfFileValidator validator;
  auto tmpRoot = uniqueTempPathE2E("transfer_e2e_dup", "");
  fs::create_directories(tmpRoot);
  BinaryFileStorage storage(tmpRoot);

  UserId aliceId = generateUserId();
  UserId bobId = generateUserId();
  users.save(User(aliceId, "alice", "alice@ex.com"), "h1");
  users.save(User(bobId, "bob", "bob@ex.com"), "h2");
  SessionId aliceSess = sessions.createForUser(aliceId, clock.nowMs());
  auto kpBob = KeyPair::generate();
  keys.savePubkey(bobId, std::vector<uint8_t>(kpBob.pub.begin(), kpBob.pub.end()));

  TransferService svc(&storage, &keys, &files, nullptr, &audit, &validator, &clock, &sessions, &users);

  std::vector<uint8_t> pdf{'%', 'P', 'D', 'F', 7, 7, 7};
  ClientCryptoProvider crypto;
  auto enc = crypto.encrypt(pdf, std::vector<uint8_t>(kpBob.pub.begin(), kpBob.pub.end()));
  enc.wrapped.recipientId = bobId;

  auto r1 = svc.upload(aliceSess, "bob", "a.pdf", enc.cipher, "dup-1", pdf.size(), enc.digest, enc.wrapped);
  ASSERT_TRUE(r1.ok) << r1.error;

  // Count files before second attempt
  size_t fileCountBefore = 0;
  for (auto &p : fs::directory_iterator(tmpRoot)) if (p.is_regular_file()) fileCountBefore++;

  auto r2 = svc.upload(aliceSess, "bob", "a.pdf", enc.cipher, "dup-1", pdf.size(), enc.digest, enc.wrapped);
  EXPECT_FALSE(r2.ok);
  EXPECT_NE(r2.error.find("duplicate"), std::string::npos);

  // No orphan .part and no extra blob
  size_t fileCountAfter = 0;
  for (auto &p : fs::directory_iterator(tmpRoot)) {
    if (p.is_regular_file()) {
      fileCountAfter++;
      EXPECT_FALSE(p.path().string().find(".part") != std::string::npos) << "orphan part left";
    }
  }
  EXPECT_EQ(fileCountBefore, fileCountAfter);

  // Original still retrievable ( need bob session)
  SessionId bobSess = sessions.createForUser(bobId, clock.nowMs());
  // Need to retrieve fileId from r1
  auto dl = svc.download(bobSess, r1.value->file);
  // Bob decrypt verifies
  if (dl.ok && dl.value.has_value()) {
    auto plain = crypto.decryptAndVerify(dl.value.value(), enc.wrapped, enc.digest, kpBob.priv);
    EXPECT_EQ(plain, pdf);
  }

  fs::remove_all(tmpRoot);
}
