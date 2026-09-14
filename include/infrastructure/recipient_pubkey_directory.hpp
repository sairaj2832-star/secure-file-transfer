#pragma once
#include "ports/key_directory.hpp"
#include <string>
#include <sqlite3.h>

class SqlitePubkeyDirectory : public IKeyDirectory {
 public:
  explicit SqlitePubkeyDirectory(const std::string& dbPath);
  ~SqlitePubkeyDirectory() override;
  void savePubkey(const UserId& uid, const std::vector<uint8_t>& pub) override;
  std::vector<uint8_t> getPubkey(const UserId& uid) const override;
  bool exists(const UserId& uid) const override;
  std::vector<UserId> listAll() const override;
 private:
  std::string dbPath_;
  sqlite3* db_ = nullptr;
  void exec(const std::string& sql) const;
};
