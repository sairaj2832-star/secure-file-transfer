#pragma once
#include "ports/storage.hpp"
#include "ports/file_repository.hpp"
#include "domain/exceptions.hpp"
#include <string>
#include <vector>
#include <cstddef>

class BinaryFileStorage : public IStorage {
 public:
  explicit BinaryFileStorage(std::string root);
  // IStorage
  void write(const std::string& k, const std::vector<uint8_t>& v) override;
  std::vector<uint8_t> read(const std::string& k) const override;

  // staged crash-safe API
  void stagedWrite(const std::string& storageId, const std::vector<uint8_t>& data);
  void removeStaged(const std::string& storageId);
  size_t sweepOrphans(const std::string& root, IFileRepository* repo);
  // convenience overload using internal root_
  size_t sweepOrphans(IFileRepository* repo);

  const std::string& root() const { return root_; }

 private:
  std::string root_;
  void ensureRootExists() const;
  void fsyncFile(const std::string& path) const;
  void fsyncDir(const std::string& dir) const;
};
