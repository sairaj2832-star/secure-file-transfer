// include/infrastructure/asio_tls_transport.hpp — real TLS 1.3 with verify_peer, DER fingerprint
#pragma once
#include "ports/transport.hpp"
#include "ports/transport_listener.hpp"
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <string>
#include <memory>
class AsioTlsTransport : public ITransport {
 public:
  explicit AsioTlsTransport(TrustConfig cfg);
  // For server-accepted sockets (already handshaked)
  AsioTlsTransport(TrustConfig cfg, asio::ssl::stream<asio::ip::tcp::socket>&& stream);
  ~AsioTlsTransport() override;
  void connect(const std::string& host, uint16_t port) override;
  void sendFrame(const Frame& f) override;
  bool recvFrame(Frame& out, int timeoutMs) override;
  void close() override;
 private:
  struct Impl;
  std::unique_ptr<Impl> pimpl_;
  TrustConfig cfg_;
  bool verifyFingerprint(X509* cert) const;
  std::string computeDerFingerprint(X509* cert) const;
};
