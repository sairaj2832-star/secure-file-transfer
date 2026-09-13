// include/infrastructure/sqlite_user_repo.hpp
#pragma once
#include "ports/user_repository.hpp"
#include <string>
#include <sqlite3.h>
class SqliteUserRepository : public IUserRepository {
 public:
  explicit SqliteUserRepository(const std::string& dbPath);
  ~SqliteUserRepository() override;
  Result<User> findByUsername(const std::string& name) const override;
  Result<User> findByEmail(const std::string& email) const override;
  Result<User> findById(const UserId& id) const override;
  void save(const User& u, const std::string& encodedHash) override;
  void update(const User& u) override;
  void updateHash(const UserId& id, const std::string& h) override;
  void recordLoginFailure(const UserId& id, int f, int64_t until) override;
  void resetLoginFailures(const UserId& id) override;
  std::string getEncodedHash(const UserId& id) const override;
  std::vector<User> listAll() const override;
 private:
  sqlite3* db_=nullptr;
  void exec(const std::string& sql) const;
  Result<User> findByColumn(const std::string& col, const std::string& val) const;
};
