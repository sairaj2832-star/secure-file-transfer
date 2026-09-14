// include/infrastructure/memory_storage.hpp
#pragma once
#include "ports/storage.hpp"
#include "domain/exceptions.hpp"
#include <unordered_map>
class MemoryStorage : public IStorage {
 public:
  void write(const std::string& k, const std::vector<uint8_t>& v) override { m_[k] = v; }
  std::vector<uint8_t> read(const std::string& k) const override {
    auto it = m_.find(k);
    if (it == m_.end()) throw NotFoundException("missing blob");
    return it->second;
  }
  void stagedWrite(const std::string& storageId, const std::vector<uint8_t>& data) override { m_[storageId] = data; }
  void removeStaged(const std::string& storageId) override { m_.erase(storageId); std::string tmp = "tmp." + storageId + ".part"; m_.erase(tmp); }
 private:
  std::unordered_map<std::string, std::vector<uint8_t>> m_;
};