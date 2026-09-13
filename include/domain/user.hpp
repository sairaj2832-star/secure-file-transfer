// include/domain/user.hpp
#pragma once
#include "domain/ids.hpp"
#include "domain/exceptions.hpp"
#include <string>
class User {
 public:
  User(UserId id, std::string username, std::string passHash, std::string role="user", std::string status="active")
      : id_(id), username_(std::move(username)), passHash_(std::move(passHash)), role_(role), status_(status) {
    if (username_.empty()) throw ValidationException("username empty");
  }
  virtual ~User() = default;
  const UserId& id() const { return id_; }
  bool canLogin() const { return status_ == "active"; }
 private:
  UserId id_; std::string username_, passHash_, role_, status_;
};
class RegularUser : public User { public: using User::User; };
class Administrator : public User { public: using User::User; };