#include <gtest/gtest.h>
#include "infrastructure/sqlite_file_repo.hpp"
#include "infrastructure/memory_file_repo.hpp"
#include "domain/ids.hpp"
#include "domain/file_record.hpp"
#include "domain/exceptions.hpp"
#include <filesystem>
#include <vector>

namespace fs = std::filesystem;

static std::string uniqueTempPathSqlite(const std::string& prefix, const std::string& ext){
  return (fs::temp_directory_path() / (prefix + "_" + generateSessionId().value + ext)).string();
}

TEST(SqliteFileRepo, UniqueUploadId){
  auto db = uniqueTempPathSqlite("filerepo",".db");
  fs::remove(db);
  fs::remove(db+"-wal");
  fs::remove(db+"-shm");
  {
    SqliteFileRepository repo(db);
    FileRecord r;
    r.id = FileId{generateUserId().value};
    r.uploadId = "uuid-1";
    r.storageId = "uuid1.bin";
    r.origName = "a.pdf";
    r.owner = generateUserId();
    r.recipient = generateUserId();
    r.size = 123;
    repo.save(r);
    FileRecord r2 = r;
    r2.id = FileId{generateUserId().value};
    r2.storageId = "uuid2.bin";
    // duplicate uploadId should throw ValidationException
    EXPECT_THROW(repo.save(r2), ValidationException);
  }
  fs::remove(db); fs::remove(db+"-wal"); fs::remove(db+"-shm");
}

TEST(SqliteFileRepo, PersistsAndFinds){
  auto db = uniqueTempPathSqlite("filerepo2",".db");
  fs::remove(db);
  fs::remove(db+"-wal");
  fs::remove(db+"-shm");
  {
    SqliteFileRepository repo(db);
    FileRecord r;
    r.id = FileId{"fid1"};
    r.uploadId = "u1";
    r.storageId = "s1.bin";
    r.origName = "a.pdf";
    r.owner = generateUserId();
    r.recipient = generateUserId();
    r.size = 42;
    repo.save(r);
  }
  {
    SqliteFileRepository repo(db);
    auto res = repo.findById(FileId{"fid1"});
    ASSERT_TRUE(res.ok && res.value.has_value());
    EXPECT_EQ(res.value->storageId, "s1.bin");
    EXPECT_EQ(res.value->origName, "a.pdf");
    // findByOwner
    auto owner = res.value->owner;
    auto list = repo.findByOwner(owner);
    ASSERT_EQ(list.size(), 1u);
    EXPECT_EQ(list[0].storageId, "s1.bin");
    // existsUploadId
    EXPECT_TRUE(repo.existsUploadId("u1"));
    EXPECT_FALSE(repo.existsUploadId("nonexistent"));
  }
  fs::remove(db); fs::remove(db+"-wal"); fs::remove(db+"-shm");
}

TEST(SqliteFileRepo, RollbackOnFail){
  auto db = uniqueTempPathSqlite("filerepo3",".db");
  fs::remove(db);
  fs::remove(db+"-wal");
  fs::remove(db+"-shm");
  {
    SqliteFileRepository repo(db);
    FileRecord r;
    r.id = FileId{"fid-rollback-1"};
    r.uploadId = "rollback-1";
    r.storageId = "rollback1.bin";
    r.origName = "a.pdf";
    r.owner = generateUserId();
    r.recipient = generateUserId();
    repo.save(r);
    // attempt duplicate uploadId - should rollback and not insert second row
    FileRecord r2 = r;
    r2.id = FileId{"fid-rollback-2"};
    r2.storageId = "rollback2.bin";
    // same uploadId
    EXPECT_THROW(repo.save(r2), ValidationException);
    // DB should still have only first row, no orphan row for fid-rollback-2
    auto res1 = repo.findById(FileId{"fid-rollback-1"});
    ASSERT_TRUE(res1.ok && res1.value.has_value());
    auto res2 = repo.findById(FileId{"fid-rollback-2"});
    EXPECT_FALSE(res2.ok);
    EXPECT_FALSE(repo.existsUploadId("nonexistent-but-check"));
    // also verify count via findByOwner size remains 1
    auto list = repo.findByOwner(r.owner);
    EXPECT_EQ(list.size(), 1u);
  }
  fs::remove(db); fs::remove(db+"-wal"); fs::remove(db+"-shm");
}
