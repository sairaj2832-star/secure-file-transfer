// include/infrastructure/fake_transport.hpp
#pragma once
#include "ports/transport.hpp"
#include <deque>
#include <mutex>
class FakeTransport : public ITransport {
 public:
  void connect(const std::string&, uint16_t) override {}
  void sendFrame(const Frame& f) override {
    auto wire = encodeFrame(f);
    std::lock_guard<std::mutex> lk(mtx_);
    queue_.push_back(wire);
  }
  bool recvFrame(Frame& out, int) override {
    std::lock_guard<std::mutex> lk(mtx_);
    if (queue_.empty()) return false;
    std::vector<uint8_t> wire = queue_.front();
    queue_.pop_front();
    size_t used = 0;
    if (!tryDecode(wire, out, used)) return false;
    return true;
  }
  void close() override {}
  static std::deque<std::vector<uint8_t>> queue_;
  static std::mutex mtx_;
};
inline std::deque<std::vector<uint8_t>> FakeTransport::queue_;
inline std::mutex FakeTransport::mtx_;