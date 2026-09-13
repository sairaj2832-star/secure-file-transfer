// include/domain/download_token.hpp
#pragma once
#include "domain/ids.hpp"
#include <cstdint>
#include <string>
struct DownloadToken {
  std::string tokenHash; FileId file; UserId creator, bind;
  int64_t expiresAt = 4102444800; int maxUses = 1; int useCount = 0; bool revoked = false;
  bool validFor(const UserId& u, int64_t now) const {
    if (revoked) return false;
    if (!(bind == u)) return false;
    if (now > expiresAt) return false;
    if (useCount >= maxUses) return false;
    return true;
  }
};