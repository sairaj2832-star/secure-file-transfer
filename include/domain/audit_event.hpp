// include/domain/audit_event.hpp
#pragma once
#include <cstdint>
#include <string>
struct AuditEvent { uint64_t seq = 0; std::string ts, actor, action, fileId, cipherHash, prevHash, msgHash; };
namespace AuditAction {
  inline constexpr const char* REGISTER_OK="REGISTER_OK"; inline constexpr const char* REGISTER_FAIL="REGISTER_FAIL";
  inline constexpr const char* LOGIN_OK="LOGIN_OK"; inline constexpr const char* LOGIN_FAIL="LOGIN_FAIL";
  inline constexpr const char* LOGOUT="LOGOUT"; inline constexpr const char* ACTIVATE="ACTIVATE";
  inline constexpr const char* DEACTIVATE="DEACTIVATE"; inline constexpr const char* ADMIN_DENIED="ADMIN_DENIED";
  inline constexpr const char* TLS_FAIL="TLS_FAIL";
}
