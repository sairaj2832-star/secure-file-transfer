// tests/presentation/test_cli.cpp
#include <gtest/gtest.h>
#include "presentation/cli.hpp"
#include <sstream>
TEST(Cli, YesNo) {
  std::istringstream in("y\n");
  EXPECT_TRUE(askYesNo("Upload a.pdf for Bob?", in));
  std::istringstream in2("n\n");
  EXPECT_FALSE(askYesNo("Download?", in2));
}