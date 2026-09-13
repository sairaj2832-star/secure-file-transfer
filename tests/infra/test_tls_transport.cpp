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
  TrustConfig c;
  for(auto p : {"./certs/test_server.crt", "../certs/test_server.crt", "D:/OOPS/CP/certs/test_server.crt"}){
    if(std::filesystem::exists(p)){ c.certPath=p; c.keyPath= std::string(p).substr(0, std::string(p).find("test_server.crt"))+"test_server.key"; c.caPath=p; break; }
  }
  if(c.certPath.empty()) c.certPath="./certs/test_server.crt";
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
  AsioTlsListener listener(good);
  uint16_t port = listener.listen(0);
  std::thread srv([&]{ try{ auto c=listener.accept(); Frame f; c->recvFrame(f,1000);}catch(...){} });
  AsioTlsTransport client(bad);
  EXPECT_THROW(client.connect("127.0.0.1", port), TransportException);
  // client-side fingerprint mismatch is audited on client, not server
  if(srv.joinable()) srv.join();
  listener.close();
}
TEST(TlsTransport, NoVerifyNoneInProd) {
  auto readSrc = [](const std::string& rel){
    for(auto p : {rel, std::string("../")+rel, std::string("D:/OOPS/CP/")+rel}){
      std::ifstream f(p);
      if(f) return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    }
    return std::string();
  };
  std::string src = readSrc("src/infrastructure/asio_tls_transport.cpp");
  EXPECT_EQ(src.find("verify_none"), std::string::npos);
  std::string src2 = readSrc("src/infrastructure/asio_tls_listener.cpp");
  EXPECT_EQ(src2.find("verify_none"), std::string::npos);
}
