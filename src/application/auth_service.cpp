#include "application/auth_service.hpp"
#include "domain/exceptions.hpp"
Result<UserId> AuthService::registerUser(const std::string& u, const std::string& email, const std::string& pw, const std::string& role){
  if (u.empty() || email.empty() || pw.size()<8) return Result<UserId>::failure("Registration failed");
  if (repo_->findByUsername(u).ok || repo_->findByEmail(email).ok){
    audit_->record({0,"", "system", AuditAction::REGISTER_FAIL, "", "", "", ""});
    return Result<UserId>::failure("Registration failed");
  }
  std::string encoded = hasher_->hash(pw);
  UserId newId = generateUserId();
  User nu(newId, u, email, role, "active");
  repo_->save(nu, encoded);
  audit_->record({0,"", u, AuditAction::REGISTER_OK, "", "", "", ""});
  return Result<UserId>::success(newId);
}
Result<SessionId> AuthService::login(const std::string& u, const std::string& pw){
  int64_t now = clock_->nowMs();
  auto found = repo_->findByUsername(u);
  if (!found.ok || !found.value.has_value()){ audit_->record({0,"", u, AuditAction::LOGIN_FAIL, "", "", "", ""}); return Result<SessionId>::failure("Login failed"); }
  User user = found.value.value();
  if (!user.canLogin(now)){ audit_->record({0,"", u, AuditAction::LOGIN_FAIL, "", "", "", ""}); return Result<SessionId>::failure("Login failed"); }
  std::string enc = repo_->getEncodedHash(user.id());
  if (!hasher_->verify(enc, pw)){
    int fails = user.failedAttempts()+1;
    int64_t lockout = fails>=MAX_FAILS ? now+LOCKOUT_MS : user.lockoutUntil();
    repo_->recordLoginFailure(user.id(), fails, lockout);
    audit_->record({0,"", u, AuditAction::LOGIN_FAIL, "", "", "", ""});
    return Result<SessionId>::failure("Login failed");
  }
  repo_->resetLoginFailures(user.id());
  SessionId token = sessions_->createForUser(user.id(), now);
  audit_->record({0,"", u, AuditAction::LOGIN_OK, "", "", "", ""});
  return Result<SessionId>::success(token);
}
bool AuthService::logout(const SessionId& tok){ auto r=sessions_->invalidate(tok); if(r) audit_->record({0,"", "", AuditAction::LOGOUT, "", "", "", ""}); return r; }
