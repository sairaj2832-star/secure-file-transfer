// include/infrastructure/hash_chain_file_audit.hpp
#pragma once
#include "ports/audit.hpp"
#include <string>
class HashChainFileAuditLogger : public IAuditLogger {
 public:
  explicit HashChainFileAuditLogger(const std::string& path);
  void record(AuditEvent e) override;
  std::vector<AuditEvent> all() const override;
  bool verify() const;
  void close();
 private:
  std::string path_;
  mutable std::string lastHash_ = "GENESIS";
  std::string canonical(const AuditEvent& e) const;
  std::string sha256hex(const std::string& s) const;
};
