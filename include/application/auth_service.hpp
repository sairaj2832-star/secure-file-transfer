// include/application/auth_service.hpp
#pragma once
#include "domain/user.hpp"
#include "domain/session.hpp"
#include "domain/result.hpp"
#include "domain/clock.hpp"
#include "ports/user_repository.hpp"
#include "ports/password_hasher.hpp"
#include "ports/audit.hpp"
#include "ports/session_store.hpp"
#include <string>
class AuthService {
 public:
  AuthService(IUserRepository* repo, IPasswordHasher* hasher, ISessionStore* sessions, IAuditLogger* audit, IClock* clock)
    : repo_(repo), hasher_(hasher), sessions_(sessions), audit_(audit), clock_(clock) {}
  Result<UserId> registerUser(const std::string& username, const std::string& email, const std::string& password, const std::string& role="user");
  Result<SessionId> login(const std::string& username, const std::string& password);
  bool logout(const SessionId& token);
 private:
  IUserRepository* repo_; IPasswordHasher* hasher_; ISessionStore* sessions_; IAuditLogger* audit_; IClock* clock_;
  static constexpr int MAX_FAILS=5; static constexpr int64_t LOCKOUT_MS=15*60*1000;
};
