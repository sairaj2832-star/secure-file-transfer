// include/infrastructure/fake_listener.hpp — tests only
#pragma once
#include "ports/transport_listener.hpp"
#include "infrastructure/fake_transport.hpp"
#include <queue>
class FakeListener : public ITransportListener {
 public:
  uint16_t listen(uint16_t port) override { (void)port; return 0; }
  std::unique_ptr<ITransport> accept() override { return std::make_unique<FakeTransport>(); }
  void close() override {}
};
