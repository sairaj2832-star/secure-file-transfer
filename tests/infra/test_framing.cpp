// tests/infra/test_framing.cpp
#include <gtest/gtest.h>
#include "ports/transport.hpp"
TEST(Framing, SplitCoalesced) {
  Frame f{MsgType::DATA, 7, {1,2,3,4}};
  auto wire = encodeFrame(f);
  // split delivery
  std::vector<uint8_t> half(wire.begin(), wire.begin() + 3);
  Frame out; size_t used = 0;
  EXPECT_FALSE(tryDecode(half, out, used));
  // coalesced delivery (two frames back-to-back)
  auto wire2 = encodeFrame(f);
  std::vector<uint8_t> both = wire; both.insert(both.end(), wire2.begin(), wire2.end());
  EXPECT_TRUE(tryDecode(both, out, used));
  EXPECT_EQ(out.requestId, 7u);
}