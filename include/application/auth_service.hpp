// include/application/auth_service.hpp
#pragma once
#include "domain/ids.hpp"
#include "domain/user.hpp"
#include "domain/result.hpp"
#include <map>
class AuthService {
 public:
  Result<User> regist(const std::string& name, const std::string& pw);
  Result<User> login(const std::string& name, const std::string& pw) const;
 private:
  std::map<std::string, User> users_;
};