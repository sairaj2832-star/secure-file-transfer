// tests/infra/test_client_crypto.cpp — Task 4 ClientCryptoProvider TDD
#include <gtest/gtest.h>
#include "infrastructure/client_crypto.hpp"
#include "domain/key_pair.hpp"
#include "domain/exceptions.hpp"
#include <set>
#include <string>

TEST(ClientCrypto, RoundTrip){
  auto kp = KeyPair::generate();
  ClientCryptoProvider crypto(kp.pub);
  std::vector<uint8_t> plain{'h','e','l','l','o'};
  auto out = crypto.encrypt(plain, kp.pub);
  EXPECT_EQ(out.wrapped.nonce.size(), 12u);
  EXPECT_FALSE(out.wrapped.bytes.empty());
  auto back = crypto.decryptAndVerify(out.cipher, out.wrapped, out.digest, kp.priv);
  EXPECT_EQ(back, plain);
}

TEST(ClientCrypto, NonceUniq10k){
  auto kp=KeyPair::generate();
  ClientCryptoProvider c(kp.pub);
  std::set<std::string> nonces;
  for(int i=0;i<10000;i++){
    auto o=c.encrypt(std::vector<uint8_t>{1,2,3}, kp.pub);
    nonces.insert(std::string(reinterpret_cast<const char*>(o.wrapped.nonce.data()), o.wrapped.nonce.size()));
  }
  EXPECT_EQ(nonces.size(), 10000u);
}

TEST(ClientCrypto, TagFailOnTamper){
  auto kp=KeyPair::generate();
  ClientCryptoProvider c(kp.pub);
  auto o=c.encrypt(std::vector<uint8_t>{9,9,9}, kp.pub);
  ASSERT_FALSE(o.cipher.empty());
  o.cipher[0]^=1;
  EXPECT_THROW(c.decryptAndVerify(o.cipher, o.wrapped, o.digest, kp.priv), IntegrityException);
}

TEST(ClientCrypto, WrongKeyFails){
  auto a=KeyPair::generate();
  auto b=KeyPair::generate();
  ClientCryptoProvider c(a.pub);
  auto o=c.encrypt(std::vector<uint8_t>{7}, a.pub);
  EXPECT_THROW(c.decryptAndVerify(o.cipher, o.wrapped, o.digest, b.priv), IntegrityException);
}

TEST(ClientCrypto, ServerHexdumpDiffers){
  auto kp=KeyPair::generate();
  ClientCryptoProvider c(kp.pub);
  std::vector<uint8_t> pdf{'%','P','D','F',1,2,3};
  auto o=c.encrypt(pdf, kp.pub);
  EXPECT_NE(o.cipher, pdf);
  // ensure not trivially equal even as string
  EXPECT_NE(std::string(o.cipher.begin(), o.cipher.end()), std::string(pdf.begin(), pdf.end()));
  // also ensure at least one byte differs
  bool anyDiff = false;
  if (o.cipher.size() != pdf.size()) anyDiff = true;
  else {
    for (size_t i=0;i<pdf.size();++i) if (o.cipher[i]!=pdf[i]) { anyDiff=true; break; }
  }
  EXPECT_TRUE(anyDiff);
}
