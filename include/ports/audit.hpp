// include/ports/audit.hpp
#pragma once
#include "domain/audit_event.hpp"
#include <vector>
class IAuditLogger { public: virtual ~IAuditLogger() = default; virtual void record(AuditEvent e) = 0; virtual std::vector<AuditEvent> all() const = 0; };