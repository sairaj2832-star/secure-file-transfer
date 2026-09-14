#pragma once
#include "domain/transfer.hpp"
#include "domain/result.hpp"
#include <vector>

class ITransferRepository {
 public:
  virtual ~ITransferRepository() = default;
  virtual void save(const Transfer&) = 0;
  virtual Result<Transfer> findById(const TransferId&) const = 0;
  virtual std::vector<Transfer> listFor(const UserId&) const = 0;
};
