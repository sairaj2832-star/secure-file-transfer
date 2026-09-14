#include <gtest/gtest.h>
#include "infrastructure/binary_storage.hpp"
#include "ports/file_repository.hpp"
#include "domain/file_record.hpp"
#include "domain/result.hpp"
#include "domain/ids.hpp"
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

static std::string uniqueTempPath(const std::string& prefix, const std::string& ext){
  return (fs::temp_directory_path() / (prefix + "_" + generateSessionId().value + ext)).string();
}

// Minimal fake IFileRepository that holds no entries — for orphan sweeper test
class FakeFileRepo : public IFileRepository {
 public:
  void save(const FileRecord&) override {}
  Result<FileRecord> findById(const FileId&) const override { return Result<FileRecord>::failure("not found"); }
  std::vector<FileRecord> findByOwner(const UserId&) const override { return {}; }
  bool existsUploadId(const std::string&) const override { return false; }
};

TEST(BinaryStorage, StagedWriteSucceeds){
  auto root = uniqueTempPath("blobtest",""); fs::create_directories(root);
  BinaryFileStorage st(root);
  st.stagedWrite("uuid1.bin", {1,2,3});
  EXPECT_EQ(st.read("uuid1.bin"), std::vector<uint8_t>({1,2,3}));
  EXPECT_FALSE(fs::exists(root+"/uuid1.bin.part"));
  EXPECT_FALSE(fs::exists(root+"/tmp.uuid1.bin.part"));
  fs::remove_all(root);
}

TEST(BinaryStorage, SweepDeletesOrphanPart){
  auto root=uniqueTempPath("blobtest2",""); fs::create_directories(root);
  BinaryFileStorage st(root);
  // simulate crash: write .part without rename
  {
    std::ofstream f(root+"/orphan.bin.part", std::ios::binary);
    f.write("x",1);
  }
  ASSERT_TRUE(fs::exists(root+"/orphan.bin.part"));
  FakeFileRepo fakeRepo; // no entry for orphan
  EXPECT_EQ(st.sweepOrphans(root, &fakeRepo), 1u);
  EXPECT_FALSE(fs::exists(root+"/orphan.bin.part"));
  // also test tmp. prefix orphan
  {
    std::ofstream f(root+"/tmp.stale.bin.part", std::ios::binary);
    f.write("y",1);
  }
  EXPECT_EQ(st.sweepOrphans(root, &fakeRepo), 1u);
  EXPECT_FALSE(fs::exists(root+"/tmp.stale.bin.part"));
  fs::remove_all(root);
}

TEST(BinaryStorage, IdempotentRename){
  auto root=uniqueTempPath("blobtest3",""); fs::create_directories(root);
  BinaryFileStorage st(root);
  st.stagedWrite("uuid2.bin", {9});
  st.stagedWrite("uuid2.bin", {9}); // second should overwrite atomically via tmp+rename, no throw
  EXPECT_EQ(st.read("uuid2.bin").size(), 1u);
  EXPECT_EQ(st.read("uuid2.bin"), std::vector<uint8_t>({9}));
  EXPECT_FALSE(fs::exists(root+"/tmp.uuid2.bin.part"));
  fs::remove_all(root);
}
