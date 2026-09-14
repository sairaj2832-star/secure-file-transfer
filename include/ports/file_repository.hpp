#pragma once
#include "domain/file_record.hpp"
#include "domain/result.hpp"
#include <string>
#include <vector>

class IFileRepository {
 public:
  virtual ~IFileRepository() = default;
  virtual void save(const FileRecord&) = 0;
  virtual Result<FileRecord> findById(const FileId&) const = 0;
  virtual std::vector<FileRecord> findByOwner(const UserId&) const = 0;
  virtual bool existsUploadId(const std::string&) const = 0;
};
