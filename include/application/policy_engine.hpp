// include/application/policy_engine.hpp
#pragma once
#include "ports/policy.hpp"
#include <map>
#include <set>
class PolicyEngine : public IAccessPolicy {
 public:
  void grant(const FileId& f, const UserId& u) { grants_[f.value].insert(u.value); }
  bool isAuthorized(const UserId& u, const FileRecord& f) const override {
    if (f.isOwnedBy(u)) return true;
    auto it = grants_.find(f.id.value);
    return it != grants_.end() && it->second.count(u.value) > 0;
  }
 private:
  std::map<std::string, std::set<std::string>> grants_;
};