#pragma once
#include "ports/file_repository.hpp"
#include <string>
#include <sqlite3.h>

class SqliteFileRepository : public IFileRepository {
 public:
  explicit SqliteFileRepository(const std::string& dbPath);
  ~SqliteFileRepository() override;
  void save(const FileRecord& r) override;
  Result<FileRecord> findById(const FileId& id) const override;
  std::vector<FileRecord> findByOwner(const UserId& owner) const override;
  bool existsUploadId(const std::string& uploadId) const override;

 private:
  std::string dbPath_;
  sqlite3* db_ = nullptr;
  void exec(const std::string& sql) const;
};
