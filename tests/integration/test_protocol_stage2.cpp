#include <gtest/gtest.h>
#include "presentation/protocol.hpp"
#include "domain/ids.hpp"
#include "domain/wrapped_key.hpp"

TEST(ProtocolStage2, UploadInitRoundTrip){
  auto uid = generateUserId();
  WrappedKey w{uid, std::vector<uint8_t>(12,1), std::vector<uint8_t>(48,2), "X25519-AES-GCM-Seal"};
  UploadInit init{"bob","doc.pdf","uuid-1", 123, Digest{}, w};
  auto body = encodeUploadInit(init);
  auto dec = decodeUploadInit(body);
  EXPECT_EQ(dec.recipient,"bob");
  EXPECT_EQ(dec.origName,"doc.pdf");
  EXPECT_EQ(dec.uploadId,"uuid-1");
  EXPECT_EQ(dec.size, 123ULL);
  EXPECT_EQ(dec.wrapped.nonce, w.nonce);
  EXPECT_EQ(dec.wrapped.bytes, w.bytes);
}

TEST(ProtocolStage2, NoPipeDelimited){
  // body contains '|' but must not confuse — prove length-prefixed survives
  UploadInit init;
  init.recipient = "b|ob";
  init.origName = "a|b.pdf";
  init.uploadId = "u|1";
  init.size = 5;
  init.digest = Digest{};
  // wrapped empty default is allowed for this test
  auto body = encodeUploadInit(init);
  EXPECT_NO_THROW({
    auto dec = decodeUploadInit(body);
    EXPECT_EQ(dec.recipient, "b|ob");
    EXPECT_EQ(dec.origName, "a|b.pdf");
    EXPECT_EQ(dec.uploadId, "u|1");
  });
  // Also ensure pipe byte exists in raw body but decode still works
  bool hasPipe = false;
  for(auto c: body) if(c=='|') hasPipe=true;
  EXPECT_TRUE(hasPipe);
}
