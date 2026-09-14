#pragma once
#include "domain/ids.hpp"
#include <cstdint>
#include <vector>

class IKeyDirectory {
 public:
  virtual ~IKeyDirectory() = default;
  virtual void savePubkey(const UserId&, const std::vector<uint8_t>& pub) = 0;
  virtual std::vector<uint8_t> getPubkey(const UserId&) const = 0;
  virtual bool exists(const UserId&) const = 0;
  virtual std::vector<UserId> listAll() const = 0;
};
