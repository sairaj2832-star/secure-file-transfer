// include/infrastructure/memory_session_store.hpp
#pragma once
#include "ports/session_store.hpp"
#include "domain/clock.hpp"
#include <unordered_map>
class MemorySessionStore : public ISessionStore {
 public:
  explicit MemorySessionStore(IClock* c): clock_(c) {}
  SessionId createForUser(const UserId& uid, int64_t now) override;
  Result<Session> findByToken(const SessionId& token) const override;
  bool invalidate(const SessionId& token) override;
  int invalidateAllForUser(const UserId& u) override;
  bool isValid(const SessionId& token, int64_t now) const override;
 private:
  std::string hashToken(const std::string& t) const;
  IClock* clock_;
  std::unordered_map<std::string, Session> byHash_;
  std::unordered_map<std::string, std::string> userByHash_;
};
