// include/infrastructure/memory_user_repo.hpp
#pragma once
#include "ports/user_repository.hpp"
#include <unordered_map>
class MemoryUserRepository : public IUserRepository {
 public:
  Result<User> findByUsername(const std::string& n) const override;
  Result<User> findByEmail(const std::string& e) const override;
  Result<User> findById(const UserId& id) const override;
  void save(const User& u, const std::string& encodedHash) override;
  void update(const User& u) override;
  void updateHash(const UserId& id, const std::string& h) override;
  void recordLoginFailure(const UserId& id, int64_t now) override;
  void recordLoginFailure(const UserId& id, int f, int64_t until) override;
  void resetLoginFailures(const UserId& id) override;
  std::string getEncodedHash(const UserId& id) const override;
  std::vector<User> listAll() const override;
 private:
  std::unordered_map<std::string, User> usersById_;
  std::unordered_map<std::string, std::string> usernameToId_, emailToId_;
  std::unordered_map<std::string, std::string> hashById_;
};
