#include "application/admin_service.hpp"
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
