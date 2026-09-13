// include/domain/session.hpp
#pragma once
#include "domain/ids.hpp"
#include "domain/exceptions.hpp"
#include <cstdint>
#include <string>
struct Session {
  SessionId id; UserId userId; int64_t createdAt=0; int64_t expiresAt=0; bool revoked=false;
  Session() = default;
  Session(SessionId sid, UserId uid, int64_t c, int64_t e, bool rev=false): id(std::move(sid)), userId(std::move(uid)), createdAt(c), expiresAt(e), revoked(rev){
    if (createdAt>=expiresAt) throw ValidationException("session time range invalid");
  }
  bool isValid(int64_t now) const { return !revoked && now>=createdAt && now<expiresAt; }
};
