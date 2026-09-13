#include <gtest/gtest.h>
#include "presentation/cli.hpp"
#include "presentation/protocol.hpp"
TEST(CliMessages, SafeOutputsContainNoSecrets) {
  auto msg = formatSafeAuthMessage(AuditAction::REGISTER_OK, "alice");
  EXPECT_NE(msg.find("alice"), std::string::npos);
  EXPECT_EQ(msg.find("secret"), std::string::npos);
  EXPECT_EQ(msg.find("hash"), std::string::npos);
}
TEST(CliMessages, LoginFailureIsGeneric) {
  auto err = formatSafeAuthMessage(AuditAction::LOGIN_FAIL, "");
  EXPECT_EQ(err, "Login failed");
  EXPECT_EQ(err.find("not found"), std::string::npos);
  EXPECT_EQ(err.find("wrong password"), std::string::npos);
}
TEST(Protocol, LengthPrefixedRoundTrip) {
  auto payload = encodeRegister("alice", "a@ex.com", "p@ss:w0rd|with|pipes");
  auto decoded = decodeRegister(payload);
  EXPECT_EQ(decoded.username, "alice");
  EXPECT_EQ(decoded.email, "a@ex.com");
  EXPECT_EQ(decoded.password, "p@ss:w0rd|with|pipes");
}
TEST(Protocol, NoPipeDelimitedEncoding) {
  auto payload = encodeLogin("alice", "a|b");
  std::string raw(payload.begin(), payload.end());
  EXPECT_EQ(raw.find("alice|a|b"), std::string::npos);
}
