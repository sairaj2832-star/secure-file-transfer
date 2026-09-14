#include <gtest/gtest.h>
#include "infrastructure/recipient_pubkey_directory.hpp"
#include "infrastructure/memory_pubkey_directory.hpp"
#include "domain/ids.hpp"
#include "domain/exceptions.hpp"
#include <filesystem>
#include <vector>

namespace fs = std::filesystem;

static std::string uniqueTempPath(const std::string& prefix, const std::string& ext){
  return (fs::temp_directory_path() / (prefix + "_" + generateSessionId().value + ext)).string();
}

TEST(PubkeyDir, MemoryAndSqliteParity){
  auto uid=generateUserId();
  std::vector<uint8_t> pub(32,0x41);
  MemoryPubkeyDirectory mem;
  mem.savePubkey(uid, pub);
  EXPECT_EQ(mem.getPubkey(uid), pub);
  EXPECT_TRUE(mem.exists(uid));
  EXPECT_EQ(mem.listAll().size(), 1u);
}

TEST(PubkeyDir, SqlitePersistsAcrossReopen){
  auto p = uniqueTempPath("pubkey", ".db");
  fs::remove(p);
  fs::remove(p+"-wal");
  fs::remove(p+"-shm");
  auto uid=generateUserId();
  std::vector<uint8_t> pub(32,0x42);
  { SqlitePubkeyDirectory db(p); db.savePubkey(uid, pub); EXPECT_TRUE(db.exists(uid)); }
  { SqlitePubkeyDirectory db2(p); EXPECT_EQ(db2.getPubkey(uid), pub); EXPECT_TRUE(db2.exists(uid)); }
  // scoping already closed handles before remove (Windows locking)
  fs::remove(p); fs::remove(p+"-wal"); fs::remove(p+"-shm");
}

TEST(PubkeyDir, DuplicateUserThrows){
  MemoryPubkeyDirectory mem;
  auto uid=generateUserId(); std::vector<uint8_t> pub(32,1);
  mem.savePubkey(uid, pub);
  EXPECT_THROW(mem.savePubkey(uid, pub), ValidationException);
  // Sqlite duplicate too
  auto p = uniqueTempPath("pubkey_dup", ".db");
  fs::remove(p); fs::remove(p+"-wal"); fs::remove(p+"-shm");
  {
    SqlitePubkeyDirectory db(p);
    auto uid2=generateUserId();
    std::vector<uint8_t> pub2(32,2);
    db.savePubkey(uid2, pub2);
    EXPECT_THROW(db.savePubkey(uid2, pub2), ValidationException);
  }
  fs::remove(p); fs::remove(p+"-wal"); fs::remove(p+"-shm");
}

TEST(PubkeyDir, NotFoundThrows){
  MemoryPubkeyDirectory mem;
  auto uid=generateUserId();
  EXPECT_THROW(mem.getPubkey(uid), NotFoundException);
  EXPECT_FALSE(mem.exists(uid));
  auto p = uniqueTempPath("pubkey_nf", ".db");
  fs::remove(p); fs::remove(p+"-wal"); fs::remove(p+"-shm");
  {
    SqlitePubkeyDirectory db(p);
    EXPECT_THROW(db.getPubkey(uid), NotFoundException);
    EXPECT_FALSE(db.exists(uid));
  }
  fs::remove(p); fs::remove(p+"-wal"); fs::remove(p+"-shm");
}

TEST(PubkeyDir, InvalidPubkeySizeThrows){
  MemoryPubkeyDirectory mem;
  auto uid=generateUserId();
  std::vector<uint8_t> bad11(11,0);
  std::vector<uint8_t> empty;
  std::vector<uint8_t> bad31(31,0);
  std::vector<uint8_t> bad33(33,0);
  EXPECT_THROW(mem.savePubkey(uid, bad11), ValidationException);
  EXPECT_THROW(mem.savePubkey(uid, empty), ValidationException);
  EXPECT_THROW(mem.savePubkey(uid, bad31), ValidationException);
  EXPECT_THROW(mem.savePubkey(uid, bad33), ValidationException);
  auto p = uniqueTempPath("pubkey_bad", ".db");
  fs::remove(p); fs::remove(p+"-wal"); fs::remove(p+"-shm");
  {
    SqlitePubkeyDirectory db(p);
    auto uid2=generateUserId();
    EXPECT_THROW(db.savePubkey(uid2, bad11), ValidationException);
    EXPECT_THROW(db.savePubkey(uid2, empty), ValidationException);
  }
  fs::remove(p); fs::remove(p+"-wal"); fs::remove(p+"-shm");
}
