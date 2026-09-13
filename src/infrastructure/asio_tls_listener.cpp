#include "infrastructure/asio_tls_listener.hpp"
#include "infrastructure/asio_tls_transport.hpp"
#include <asio.hpp>
#include <memory>
using asio::ip::tcp;
struct AsioTlsListener::Impl {
  asio::io_context ioctx;
  std::unique_ptr<tcp::acceptor> acceptor;
  TrustConfig cfg;
};
AsioTlsListener::AsioTlsListener(TrustConfig cfg): pimpl_(std::make_unique<Impl>()){
  pimpl_->cfg = std::move(cfg);
}
AsioTlsListener::~AsioTlsListener(){ close(); }
uint16_t AsioTlsListener::listen(uint16_t port){
  pimpl_->acceptor = std::make_unique<tcp::acceptor>(pimpl_->ioctx, tcp::endpoint(tcp::v4(), port));
  pimpl_->acceptor->set_option(tcp::acceptor::reuse_address(true));
  return pimpl_->acceptor->local_endpoint().port();
}
std::unique_ptr<ITransport> AsioTlsListener::accept(){
  tcp::socket sock(pimpl_->ioctx);
  pimpl_->acceptor->accept(sock);
  auto transport = std::make_unique<AsioTlsTransport>(pimpl_->cfg, std::move(sock));
  return transport;
}
void AsioTlsListener::close(){
  if(pimpl_ && pimpl_->acceptor && pimpl_->acceptor->is_open()){
    asio::error_code ec; pimpl_->acceptor->close(ec);
  }
}
