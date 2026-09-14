#pragma once
#include "ports/key_directory.hpp"
#include <unordered_map>
#include <string>
#include <vector>

class MemoryPubkeyDirectory : public IKeyDirectory {
 public:
  void savePubkey(const UserId& uid, const std::vector<uint8_t>& pub) override;
  std::vector<uint8_t> getPubkey(const UserId& uid) const override;
  bool exists(const UserId& uid) const override;
  std::vector<UserId> listAll() const override;
 private:
  std::unordered_map<std::string, std::vector<uint8_t>> store_;
};
