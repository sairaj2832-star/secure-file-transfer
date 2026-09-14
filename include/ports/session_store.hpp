// include/ports/session_store.hpp
#pragma once
#include "domain/session.hpp"
#include "domain/result.hpp"
class ISessionStore {
 public:
  virtual ~ISessionStore()=default;
  virtual SessionId createForUser(const UserId& uid, int64_t now) = 0;
  virtual Result<Session> findByToken(const SessionId& token) const = 0;
  virtual bool invalidate(const SessionId& token) = 0;
  virtual int invalidateAllForUser(const UserId& u) = 0;
  virtual bool isValid(const SessionId& token, int64_t now) const = 0;
  virtual UserId userFor(const SessionId& token) const = 0;
};
