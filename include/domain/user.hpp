// include/domain/user.hpp
#pragma once
#include "domain/ids.hpp"
#include "domain/exceptions.hpp"
#include <string>
#include <cstdint>
class User {
 public:
  User(UserId id, std::string username, std::string email, std::string role="user", std::string status="active",
       int failedAttempts=0, int64_t lockoutUntil=0)
      : id_(std::move(id)), username_(std::move(username)), email_(std::move(email)), role_(role), status_(status),
        failedAttempts_(failedAttempts), lockoutUntil_(lockoutUntil) {
    if (id_.value.empty() || username_.empty() || email_.empty()) throw ValidationException("user fields empty");
  }
  virtual ~User() = default;
  const UserId& id() const { return id_; }
  const std::string& username() const { return username_; }
  const std::string& email() const { return email_; }
  const std::string& role() const { return role_; }
  const std::string& status() const { return status_; }
  int failedAttempts() const { return failedAttempts_; }
  int64_t lockoutUntil() const { return lockoutUntil_; }
  bool isAdmin() const { return role_=="admin"; }
  bool isActive() const { return status_=="active"; }
  bool canLogin(int64_t now) const { return isActive() && now>=lockoutUntil_; }
  void setStatus(const std::string& s){ status_=s; }
  void setLockout(int64_t until, int attempts){ lockoutUntil_=until; failedAttempts_=attempts; }
 private:
  UserId id_; std::string username_, email_, role_, status_;
  int failedAttempts_; int64_t lockoutUntil_;
};
class RegularUser : public User { public: using User::User; };
class Administrator : public User { public: using User::User; };
