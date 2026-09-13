// include/domain/audit_event.hpp
#pragma once
#include <cstdint>
#include <string>
struct AuditEvent { uint64_t seq = 0; std::string ts, actor, action, fileId, cipherHash, prevHash, msgHash; };