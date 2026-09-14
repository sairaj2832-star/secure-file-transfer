#include <gtest/gtest.h>
#include "domain/file_record.hpp"
#include "domain/ids.hpp"
#include "domain/exceptions.hpp"

TEST(FileRecordDomain, RejectsEmptyOrigName) {
  FileRecord r;
  r.origName = "";
  r.storageId = "dummy.bin";
  r.uploadId = "dummy-uuid";
  EXPECT_THROW(validateFileRecord(r), ValidationException);
  // also test that valid record passes
  r.origName = "doc.pdf";
  EXPECT_NO_THROW(validateFileRecord(r));
}

TEST(FileRecordDomain, IsOwnedBy) {
  auto o = generateUserId();
  FileRecord r;
  r.owner = o;
  EXPECT_TRUE(r.isOwnedBy(o));
  EXPECT_FALSE(r.isOwnedBy(generateUserId()));
}

TEST(FileRecordDomain, HasRecipientAndUploadId) {
  auto owner = generateUserId();
  auto recip = generateUserId();
  FileRecord r;
  r.id = FileId{"fid1"};
  r.owner = owner;
  r.recipient = recip;
  r.origName = "a.pdf";
  r.storageId = "uuid-123.bin";
  r.uploadId = "upload-uuid-123";
  r.size = 1024;
  r.createdAt = 1234567890;
  EXPECT_EQ(r.recipient, recip);
  EXPECT_EQ(r.storageId, "uuid-123.bin");
  EXPECT_EQ(r.uploadId, "upload-uuid-123");
  EXPECT_EQ(r.size, 1024u);
  EXPECT_TRUE(r.isOwnedBy(owner));
  EXPECT_FALSE(r.isOwnedBy(recip));
}

TEST(FileRecordDomain, DefaultWrappedIsEmptyButValid) {
  FileRecord r;
  // default WrappedKey should be default-constructed (empty) without throwing
  EXPECT_EQ(r.wrapped.nonce.size(), 0u);
  EXPECT_EQ(r.wrapped.bytes.size(), 0u);
}
