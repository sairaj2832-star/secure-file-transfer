// src/infrastructure/asio_transport.cpp
#include "infrastructure/asio_transport.hpp"
#include "ports/transport.hpp"
#include <asio.hpp>
#include <memory>
using asio::ip::tcp;
struct AsioTcpTransport::Impl {
  asio::io_context ioctx;
  std::unique_ptr<tcp::socket> socket;
  std::vector<uint8_t> rxBuf_;
};
AsioTcpTransport::AsioTcpTransport() : pimpl_(std::make_unique<Impl>()) {}
AsioTcpTransport::~AsioTcpTransport() { close(); }
void AsioTcpTransport::connect(const std::string& host, uint16_t port) {
  close();
  pimpl_ = std::make_unique<Impl>();
  tcp::resolver resolver(pimpl_->ioctx);
  auto endpoints = resolver.resolve(host, std::to_string(port));
  pimpl_->socket = std::make_unique<tcp::socket>(pimpl_->ioctx);
  asio::connect(*pimpl_->socket, endpoints);
}
void AsioTcpTransport::sendFrame(const Frame& f) {
  auto wire = encodeFrame(f);
  asio::write(*pimpl_->socket, asio::buffer(wire));
}
bool AsioTcpTransport::recvFrame(Frame& out, int timeoutMs) {
  asio::steady_timer timer(pimpl_->ioctx);
  timer.expires_after(std::chrono::milliseconds(timeoutMs));
  while (true) {
    if (pimpl_->rxBuf_.size() >= 4) {
      uint32_t len = get32be(pimpl_->rxBuf_.data());
      if (len > 4u*1024u*1024u) { pimpl_->rxBuf_.clear(); return false; }
      if (pimpl_->rxBuf_.size() >= 4 + len) {
        Frame tmp; tmp.type = (MsgType)pimpl_->rxBuf_[4]; tmp.requestId = get32be(pimpl_->rxBuf_.data()+5);
        tmp.body.assign(pimpl_->rxBuf_.begin()+9, pimpl_->rxBuf_.begin()+4+len);
        out = std::move(tmp);
        pimpl_->rxBuf_.erase(pimpl_->rxBuf_.begin(), pimpl_->rxBuf_.begin()+4+len);
        return true;
      }
    }
    uint8_t buf[1024];
    asio::error_code ec;
    size_t n = pimpl_->socket->read_some(asio::buffer(buf), ec);
    if (ec) return false;
    pimpl_->rxBuf_.insert(pimpl_->rxBuf_.end(), buf, buf + n);
  }
}
void AsioTcpTransport::close() {
  if (pimpl_ && pimpl_->socket && pimpl_->socket->is_open()) {
    pimpl_->socket->close();
  }
  pimpl_->rxBuf_.clear();
}