// include/infrastructure/asio_tls_transport.hpp — always TLS-like with verify_peer semantics, never verify_none
#pragma once
#include "ports/transport.hpp"
#include "ports/transport_listener.hpp"
#include <asio.hpp>
#include <string>
#include <memory>
class AsioTlsTransport : public ITransport {
 public:
  explicit AsioTlsTransport(TrustConfig cfg);
  AsioTlsTransport(TrustConfig cfg, asio::ip::tcp::socket&& sock);
  ~AsioTlsTransport() override;
  void connect(const std::string& host, uint16_t port) override;
  void sendFrame(const Frame& f) override;
  bool recvFrame(Frame& out, int timeoutMs) override;
  void close() override;
 private:
  struct Impl;
  std::unique_ptr<Impl> pimpl_;
  TrustConfig cfg_;
  bool verifyFingerprint() const;
};
