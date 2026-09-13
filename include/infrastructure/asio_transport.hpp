// include/infrastructure/asio_transport.hpp
#pragma once
#include "ports/transport.hpp"
#include <string>
#include <memory>
class AsioTcpTransport : public ITransport {
 public:
  AsioTcpTransport();
  ~AsioTcpTransport() override;
  void connect(const std::string& host, uint16_t port) override;
  void sendFrame(const Frame& f) override;
  bool recvFrame(Frame& out, int timeoutMs) override;
  void close() override;
 private:
  struct Impl;
  std::unique_ptr<Impl> pimpl_;
};