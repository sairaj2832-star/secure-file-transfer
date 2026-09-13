// tests/domain/test_entities.cpp
#include <gtest/gtest.h>
#include "domain/user.hpp"
#include "domain/file_record.hpp"
#include "domain/transfer.hpp"
#include "domain/download_token.hpp"
TEST(Entities, OwnershipAndTransfer) {
  UserId alice{"alice"}, bob{"bob"};
  RegularUser a(alice, "alice", "hash");
  EXPECT_TRUE(a.canLogin());
  FileRecord f{FileId{"f1"}, alice, "a.pdf", "uuid-1", 10, Digest{}, WrappedKey{}};
  EXPECT_TRUE(f.isOwnedBy(alice));
  EXPECT_FALSE(f.isOwnedBy(bob));
  Transfer t{TransferId{"t1"}, FileId{"f1"}, alice, bob, Transfer::Status::UPLOADED};
  t.markDownloaded();
  EXPECT_EQ(t.status, Transfer::Status::DOWNLOADED);
}
TEST(Entities, TokenBind) {
  DownloadToken tok{"h1", FileId{"f1"}, UserId{"alice"}, UserId{"bob"}};
  EXPECT_TRUE(tok.validFor(UserId{"bob"}, 0));
  EXPECT_FALSE(tok.validFor(UserId{"carol"}, 0));
}