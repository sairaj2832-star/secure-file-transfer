#include "infrastructure/asio_tls_listener.hpp"
#include "infrastructure/asio_tls_transport.hpp"
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <iostream>
using asio::ip::tcp;
struct AsioTlsListener::Impl {
  asio::io_context ioctx;
  asio::ssl::context ctx{asio::ssl::context::tlsv13_server};
  std::unique_ptr<tcp::acceptor> acceptor;
  TrustConfig cfg;
  Impl(): ctx(asio::ssl::context::tlsv13_server) {}
};
AsioTlsListener::AsioTlsListener(TrustConfig cfg): pimpl_(std::make_unique<Impl>()){
  pimpl_->cfg = std::move(cfg);
  pimpl_->ctx.set_options(asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2 | asio::ssl::context::no_tlsv1 | asio::ssl::context::no_tlsv1_1 | asio::ssl::context::no_tlsv1_2 | asio::ssl::context::single_dh_use);
  pimpl_->ctx.use_certificate_chain_file(pimpl_->cfg.certPath);
  pimpl_->ctx.use_private_key_file(pimpl_->cfg.keyPath, asio::ssl::context::pem);
  pimpl_->ctx.set_verify_mode(asio::ssl::verify_peer);
  pimpl_->ctx.set_verify_callback([](bool preverified, asio::ssl::verify_context& ctx){
    X509* cert = X509_STORE_CTX_get0_cert(ctx.native_handle());
    if(!cert) return true; // Stage 1: no client cert required
    return preverified;
  });
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
  asio::ssl::stream<tcp::socket> stream(std::move(sock), pimpl_->ctx);
  stream.handshake(asio::ssl::stream_base::server);
  auto transport = std::make_unique<AsioTlsTransport>(pimpl_->cfg, std::move(stream));
  return transport;
}
void AsioTlsListener::close(){
  if(pimpl_ && pimpl_->acceptor && pimpl_->acceptor->is_open()){
    asio::error_code ec; pimpl_->acceptor->close(ec);
  }
}
