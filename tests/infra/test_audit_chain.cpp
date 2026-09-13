#include <gtest/gtest.h>
#include "infrastructure/hash_chain_file_audit.hpp"
#include "domain/ids.hpp"
#include <filesystem>
#include <fstream>
TEST(AuditChain, DetectsTamper) {
  auto path = (std::filesystem::temp_directory_path() / ("audit_chain_" + generateSessionId().value + ".log")).string();
  std::filesystem::remove(path);
  HashChainFileAuditLogger logger(path);
  logger.record({0,"2026-01-01T00:00:00Z","alice",AuditAction::REGISTER_OK,"","", "", ""});
  logger.record({0,"2026-01-01T00:01:00Z","alice",AuditAction::LOGIN_OK,"","", "", ""});
  EXPECT_TRUE(logger.verify());
  // tamper file: flip a byte inside actor field
  {
    std::string content;
    {
      std::ifstream in(path);
      content.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    }
    size_t pos = content.find("alice");
    if(pos!=std::string::npos) content[pos]='X';
    {
      std::ofstream out(path, std::ios::trunc);
      out << content;
    }
  }
  EXPECT_FALSE(logger.verify());
  std::filesystem::remove(path);
}
