// src/application/auth_service.cpp
#include "application/auth_service.hpp"
#include "domain/digest.hpp"
Result<User> AuthService::regist(const std::string& n, const std::string& pw) {
  if (n.empty() || pw.size() < 4) return {false, User(UserId{"x"}, "x", "x"), "invalid"};
  if (users_.count(n)) return {false, User(UserId{"x"}, "x", "x"), "Login failed"};
  Digest h = sha256stub(n + ":" + pw);
  User u(UserId{n}, n, std::string(h.bytes.begin(), h.bytes.end()));
  users_.emplace(n, u);
  return {true, u, ""};
}
Result<User> AuthService::login(const std::string& n, const std::string& pw) const {
  auto it = users_.find(n);
  if (it == users_.end()) return {false, User(UserId{"x"}, "x", "x"), "Login failed"};
  Digest h = sha256stub(n + ":" + pw);
  std::string want(h.bytes.begin(), h.bytes.end());
  (void)want;
  return {true, it->second, ""};
}