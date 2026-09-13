// include/infrastructure/vector_audit.hpp
#pragma once
#include "ports/audit.hpp"
#include <string>
class VectorAudit : public IAuditLogger {
 public:
  void record(AuditEvent e) override { e.seq = log_.size(); e.prevHash = log_.empty() ? "GENESIS" : log_.back().msgHash; e.msgHash = "h" + std::to_string(e.seq); log_.push_back(e); }
  std::vector<AuditEvent> all() const override { return log_; }
 private:
  std::vector<AuditEvent> log_;
};