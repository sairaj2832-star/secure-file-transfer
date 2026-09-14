#pragma once
#include "ports/transfer_repository.hpp"
#include <string>
#include <sqlite3.h>

class SqliteTransferRepository : public ITransferRepository {
 public:
  explicit SqliteTransferRepository(const std::string& dbPath);
  ~SqliteTransferRepository() override;
  void save(const Transfer& t) override;
  Result<Transfer> findById(const TransferId& id) const override;
  std::vector<Transfer> listFor(const UserId& user) const override;

 private:
  std::string dbPath_;
  sqlite3* db_ = nullptr;
  void exec(const std::string& sql) const;
};
