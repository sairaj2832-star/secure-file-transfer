// include/ports/storage.hpp
#pragma once
#include <cstdint>
#include <string>
#include <vector>
class IStorage {
 public:
  virtual ~IStorage() = default;
  virtual void write(const std::string& k, const std::vector<uint8_t>& v) = 0;
  virtual std::vector<uint8_t> read(const std::string& k) const = 0;
  // crash-safe staged API — default delegates to write for fakes
  virtual void stagedWrite(const std::string& storageId, const std::vector<uint8_t>& data) { write(storageId, data); }
  virtual void removeStaged(const std::string& storageId) { (void)storageId; }
};