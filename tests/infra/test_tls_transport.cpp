#include <gtest/gtest.h>
#include "infrastructure/asio_tls_transport.hpp"
#include "infrastructure/asio_tls_listener.hpp"
#include "ports/transport.hpp"
#include "domain/exceptions.hpp"
#include <thread>
#include <future>
#include <filesystem>
#include <fstream>
static TrustConfig testTrust(){
  TrustConfig c; c.certPath="./certs/test_server.crt"; c.keyPath="./certs/test_server.key"; c.caPath="./certs/test_server.crt";
  c.fingerprint = computeSha256Fingerprint(c.certPath);
  return c;
}
TEST(TlsTransport, RealCertConnectSucceeds) {
  auto cfg = testTrust();
  AsioTlsListener listener(cfg);
  uint16_t port = listener.listen(0);
  ASSERT_NE(port, 0);
  std::future<bool> serverDone = std::async(std::launch::async, [&]{
    auto conn = listener.accept();
    Frame f; bool ok = conn->recvFrame(f, 2000);
    if(ok){ conn->sendFrame(Frame{MsgType::HELLO, f.requestId, {}}); }
    return ok;
  });
  AsioTlsTransport client(cfg);
  EXPECT_NO_THROW(client.connect("127.0.0.1", port));
  client.sendFrame(Frame{MsgType::HELLO, 1, {9,9}});
  EXPECT_TRUE(serverDone.get());
  client.close(); listener.close();
}
TEST(TlsTransport, MismatchedFingerprintFailsClientSide) {
  auto good = testTrust();
  auto bad = good; bad.fingerprint = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00";
  AsioTlsTransport client(bad);
  EXPECT_THROW(client.connect("127.0.0.1", 50000), TransportException);
}
TEST(TlsTransport, NoVerifyNoneInProd) {
  std::string src = [](){
    std::ifstream f("src/infrastructure/asio_tls_transport.cpp");
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  }();
  EXPECT_EQ(src.find("verify_none"), std::string::npos);
  std::string src2 = [](){
    std::ifstream f("src/infrastructure/asio_tls_listener.cpp");
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  }();
  EXPECT_EQ(src2.find("verify_none"), std::string::npos);
}
