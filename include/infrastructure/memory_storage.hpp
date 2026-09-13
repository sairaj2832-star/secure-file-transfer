// include/infrastructure/memory_storage.hpp
#pragma once
#include "ports/storage.hpp"
#include <unordered_map>
class MemoryStorage : public IStorage {
 public:
  void write(const std::string& k, const std::vector<uint8_t>& v) override { m_[k] = v; }
  std::vector<uint8_t> read(const std::string& k) const override {
    auto it = m_.find(k);
    if (it == m_.end()) throw NotFoundException("missing blob");
    return it->second;
  }
 private:
  std::unordered_map<std::string, std::vector<uint8_t>> m_;
};