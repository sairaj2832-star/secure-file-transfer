// include/ports/user_repository.hpp
#pragma once
#include "domain/user.hpp"
#include "domain/result.hpp"
#include <vector>
#include <string>
class IUserRepository {
 public:
  virtual ~IUserRepository() = default;
  virtual Result<User> findByUsername(const std::string& name) const = 0;
  virtual Result<User> findByEmail(const std::string& email) const = 0;
  virtual Result<User> findById(const UserId& id) const = 0;
  virtual void save(const User& u, const std::string& encodedHash) = 0;
  virtual void update(const User& u) = 0;
  virtual void updateHash(const UserId& id, const std::string& newEncodedHash) = 0;
  virtual void recordLoginFailure(const UserId& id, int newFailed, int64_t newLockUntil) = 0;
  virtual void resetLoginFailures(const UserId& id) = 0;
  virtual std::string getEncodedHash(const UserId& id) const = 0;
  virtual std::vector<User> listAll() const = 0;
};
