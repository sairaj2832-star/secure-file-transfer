#include "application/admin_service.hpp"
bool AdminService::isAdminSession(const SessionId& token, UserId& outId) const {
  if(!sessions_->isValid(token, clock_->nowMs())) return false;
  auto sess = sessions_->findByToken(token);
  if(!sess.ok || !sess.value.has_value()) return false;
  UserId uid = sess.value->userId;
  // recheck user active status after session validation (defense in depth for in-memory sessions)
  auto user = repo_->findById(uid);
  if(!user.ok || !user.value.has_value() || !user.value->isActive()) return false;
  outId = uid;
  return isAdmin(uid);
}
Result<UserId> AdminService::activate(const SessionId& adminToken, const UserId& tgt){
  UserId adminId;
  if(!isAdminSession(adminToken, adminId)){ audit_->record({0,"", "", AuditAction::ADMIN_DENIED, tgt.value, "", "", ""}); return Result<UserId>::failure("Admin denied"); }
  auto r=repo_->findById(tgt); if(!r.ok || !r.value.has_value()) return Result<UserId>::failure("not found");
  User u=r.value.value(); u.setStatus("active"); repo_->update(u);
  audit_->record({0,"", adminId.value, AuditAction::ACTIVATE, tgt.value, "", "", ""});
  return Result<UserId>::success(tgt);
}
Result<UserId> AdminService::deactivate(const SessionId& adminToken, const UserId& tgt){
  UserId adminId;
  if(!isAdminSession(adminToken, adminId)){ audit_->record({0,"", "", AuditAction::ADMIN_DENIED, tgt.value, "", "", ""}); return Result<UserId>::failure("Admin denied"); }
  auto r=repo_->findById(tgt); if(!r.ok || !r.value.has_value()) return Result<UserId>::failure("not found");
  User targetUser=r.value.value();
  if(targetUser.isAdmin() && targetUser.isActive() && countActiveAdmins()<=1) return Result<UserId>::failure("cannot deactivate last admin");
  // SQLite users update and in-memory session invalidation cannot be one atomic TX — commit user first, then invalidate sessions, and recheck active status on next request
  targetUser.setStatus("inactive"); repo_->update(targetUser);
  sessions_->invalidateAllForUser(tgt);
  audit_->record({0,"", adminId.value, AuditAction::DEACTIVATE, tgt.value, "", "", ""});
  return Result<UserId>::success(tgt);
}
Result<UserId> AdminService::activate(const UserId& admin, const UserId& tgt){
  if(!isAdmin(admin)){ audit_->record({0,"", admin.value, AuditAction::ADMIN_DENIED, "", "", "", ""}); return Result<UserId>::failure("Admin denied"); }
  auto r=repo_->findById(tgt); if(!r.ok || !r.value.has_value()) return Result<UserId>::failure("not found");
  User u=r.value.value(); u.setStatus("active"); repo_->update(u);
  audit_->record({0,"", admin.value, AuditAction::ACTIVATE, tgt.value, "", "", ""});
  return Result<UserId>::success(tgt);
}
Result<UserId> AdminService::deactivate(const UserId& admin, const UserId& tgt){
  if(!isAdmin(admin)){ audit_->record({0,"", admin.value, AuditAction::ADMIN_DENIED, "", "", "", ""}); return Result<UserId>::failure("Admin denied"); }
  auto r=repo_->findById(tgt); if(!r.ok || !r.value.has_value()) return Result<UserId>::failure("not found");
  User targetUser=r.value.value();
  if(targetUser.isAdmin() && targetUser.isActive() && countActiveAdmins()<=1) return Result<UserId>::failure("cannot deactivate last admin");
  targetUser.setStatus("inactive"); repo_->update(targetUser);
  sessions_->invalidateAllForUser(tgt);
  audit_->record({0,"", admin.value, AuditAction::DEACTIVATE, tgt.value, "", "", ""});
  return Result<UserId>::success(tgt);
}
bool AdminService::isAdmin(const UserId& id) const { auto r=repo_->findById(id); return r.ok && r.value.has_value() && r.value->isAdmin() && r.value->isActive(); }
int AdminService::countActiveAdmins() const { int n=0; for(auto& u: repo_->listAll()) if(u.isAdmin() && u.isActive()) n++; return n; }
