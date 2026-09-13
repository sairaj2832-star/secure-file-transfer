#include <gtest/gtest.h>
#include "infrastructure/sqlite_user_repo.hpp"
#include "infrastructure/memory_user_repo.hpp"
#include "domain/user.hpp"
#include <filesystem>
namespace fs = std::filesystem;
TEST(UserRepo, MemoryRoundTrip) {
  MemoryUserRepository r;
  auto id = generateUserId();
  User u(id, "alice", "alice@ex.com");
  r.save(u, "$argon2id$v=19$m=19456,t=2,p=1$fakehash");
  auto got = r.findByUsername("alice");
  ASSERT_TRUE(got.ok);
  ASSERT_TRUE(got.value.has_value());
  EXPECT_EQ(got.value->email(), "alice@ex.com");
  EXPECT_FALSE(r.findByUsername("nope").ok);
  EXPECT_EQ(r.getEncodedHash(id), "$argon2id$v=19$m=19456,t=2,p=1$fakehash");
}
TEST(UserRepo, SqlitePersistsAcrossReopen) {
  auto dbPath = (fs::temp_directory_path() / ("test_users_persist_" + generateSessionId().value + ".db")).string();
  fs::remove(dbPath);
  auto id = generateUserId();
  {
    SqliteUserRepository r(dbPath);
    User u(id, "alice", "alice@ex.com");
    r.save(u, "$argon2id$v=19$m=19456,t=2,p=1$hash1");
    ASSERT_TRUE(r.findByUsername("alice").ok);
  }
  {
    SqliteUserRepository r2(dbPath);
    auto got = r2.findByUsername("alice");
    ASSERT_TRUE(got.ok);
    ASSERT_TRUE(got.value.has_value());
    EXPECT_EQ(got.value->email(), "alice@ex.com");
    EXPECT_EQ(r2.getEncodedHash(id), "$argon2id$v=19$m=19456,t=2,p=1$hash1");
  }
  fs::remove(dbPath);
}
TEST(UserRepo, UniqueUsernameEmail) {
  MemoryUserRepository r;
  auto id1=generateUserId(), id2=generateUserId(), id3=generateUserId();
  User u1(id1, "alice", "a@ex.com");
  User u2(id2, "alice", "b@ex.com");
  r.save(u1, "$argon2id$h1");
  EXPECT_THROW(r.save(u2, "$argon2id$h2"), ValidationException);
  User u3(id3, "bob", "a@ex.com");
  EXPECT_THROW(r.save(u3, "$argon2id$h3"), ValidationException);
}
TEST(UserRepo, ImmutableUsernameEmail) {
  MemoryUserRepository r;
  auto id=generateUserId();
  User u(id, "alice", "a@ex.com");
  r.save(u, "$argon2id$h");
  auto found = r.findById(id);
  ASSERT_TRUE(found.ok && found.value.has_value());
  User modified = found.value.value();
  User withNewName(id, "alice2", "a@ex.com");
  EXPECT_THROW(r.update(withNewName), ValidationException);
}
TEST(UserRepo, AtomicRecordLoginFailure) {
  auto dbPath = (fs::temp_directory_path() / ("test_users_atomic_" + generateSessionId().value + ".db")).string();
  fs::remove(dbPath);
  {
    SqliteUserRepository r(dbPath);
    auto id=generateUserId();
    r.save(User(id, "alice", "a@ex.com"), "$argon2id$h");
    r.recordLoginFailure(id, 1, 1000);
    r.recordLoginFailure(id, 2, 2000);
    auto got = r.findById(id);
    ASSERT_TRUE(got.ok && got.value.has_value());
    auto u = got.value.value();
    EXPECT_EQ(u.failedAttempts(), 2);
    r.resetLoginFailures(id);
    auto got2 = r.findById(id);
    ASSERT_TRUE(got2.ok && got2.value.has_value());
    EXPECT_EQ(got2.value->failedAttempts(), 0);
  }
  fs::remove(dbPath);
  fs::remove(dbPath + "-wal");
  fs::remove(dbPath + "-shm");
}
