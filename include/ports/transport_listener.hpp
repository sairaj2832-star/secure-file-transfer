// include/ports/transport_listener.hpp
#pragma once
#include "ports/transport.hpp"
#include <memory>
#include <cstdint>
class ITransportListener {
 public:
  virtual ~ITransportListener()=default;
  virtual uint16_t listen(uint16_t port) = 0;
  virtual std::unique_ptr<ITransport> accept() = 0;
  virtual void close() = 0;
};
struct TrustConfig {
  std::string fingerprint;
  std::string certPath;
  std::string keyPath;
  std::string caPath;
};
std::string computeSha256Fingerprint(const std::string& certPath);
