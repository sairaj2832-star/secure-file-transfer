// src/application/auth_service.cpp — stub for Task1, will be rewritten in Task4
#include "application/auth_service.hpp"
#include "domain/digest.hpp"
Result<User> AuthService::regist(const std::string& n, const std::string& pw) {
  if (n.empty() || pw.size() < 4) return Result<User>::failure("invalid");
  if (users_.count(n)) return Result<User>::failure("Login failed");
  Digest h = sha256stub(n + ":" + pw);
  // new User no longer stores hash; for Task1 stub, store username/email only, hash ignored
  User u(generateUserId(), n, n+"@ex.com", "user", "active");
  users_.emplace(n, u);
  return Result<User>::success(u);
}
Result<User> AuthService::login(const std::string& n, const std::string& pw) const {
  auto it = users_.find(n);
  if (it == users_.end()) return Result<User>::failure("Login failed");
  // hash check stubbed for Task1
  (void)pw;
  return Result<User>::success(it->second);
}
