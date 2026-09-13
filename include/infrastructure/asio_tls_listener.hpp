// include/infrastructure/asio_tls_listener.hpp — real TLS 1.3 server
#pragma once
#include "ports/transport_listener.hpp"
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <memory>
class AsioTlsListener : public ITransportListener {
 public:
  explicit AsioTlsListener(TrustConfig cfg);
  ~AsioTlsListener() override;
  uint16_t listen(uint16_t port) override;
  std::unique_ptr<ITransport> accept() override;
  void close() override;
 private:
  struct Impl;
  std::unique_ptr<Impl> pimpl_;
  TrustConfig cfg_;
};
