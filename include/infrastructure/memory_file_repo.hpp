#pragma once
#include "ports/file_repository.hpp"
#include <unordered_map>
#include <string>

class MemoryFileRepository : public IFileRepository {
 public:
  void save(const FileRecord& r) override;
  Result<FileRecord> findById(const FileId& id) const override;
  std::vector<FileRecord> findByOwner(const UserId& owner) const override;
  bool existsUploadId(const std::string& uploadId) const override;

 private:
  std::unordered_map<std::string, FileRecord> byId_;
  std::unordered_map<std::string, std::string> uploadIdToId_;
  std::unordered_map<std::string, std::string> storageIdToId_;
};
