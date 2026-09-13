// include/application/admin_service.hpp
#pragma once
#include "domain/result.hpp"
#include "domain/user.hpp"
#include "ports/user_repository.hpp"
#include "ports/session_store.hpp"
#include "ports/audit.hpp"
#include "domain/clock.hpp"
class AdminService {
 public:
  AdminService(IUserRepository* r, ISessionStore* s, IAuditLogger* a, IClock* c): repo_(r), sessions_(s), audit_(a), clock_(c) {}
  Result<UserId> activate(const UserId& adminId, const UserId& target);
  Result<UserId> deactivate(const UserId& adminId, const UserId& target);
 private:
  bool isAdmin(const UserId& id) const;
  int countActiveAdmins() const;
  IUserRepository* repo_; ISessionStore* sessions_; IAuditLogger* audit_; IClock* clock_;
};
