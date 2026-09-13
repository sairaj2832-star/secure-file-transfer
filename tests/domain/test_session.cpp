#include <gtest/gtest.h>
#include "domain/session.hpp"
TEST(SessionDomain, ValidAndExpired) {
  Session s{SessionId{"tok1"}, UserId{"u1"}, 1000, 2000, false};
  EXPECT_TRUE(s.isValid(1500));
  EXPECT_FALSE(s.isValid(2500));
  EXPECT_FALSE(s.isValid(500));
}
TEST(SessionDomain, RevokedInvalidates) {
  Session s{SessionId{"tok1"}, UserId{"u1"}, 1000, 5000, false};
  s.revoked = true;
  EXPECT_FALSE(s.isValid(2000));
}
TEST(SessionDomain, InvariantsRejectBadRange) {
  EXPECT_THROW(Session(SessionId{"x"}, UserId{"u"}, 2000, 1000, false), ValidationException);
  EXPECT_THROW(Session(SessionId{"x"}, UserId{"u"}, 1000, 1000, false), ValidationException);
}
