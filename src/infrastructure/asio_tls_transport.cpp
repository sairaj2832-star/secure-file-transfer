#include "infrastructure/asio_tls_transport.hpp"
#include "domain/exceptions.hpp"
#include "domain/digest.hpp"
#include <asio.hpp>
#include <fstream>
#include <sstream>
using asio::ip::tcp;

std::string computeSha256Fingerprint(const std::string& certPath){
  std::ifstream f(certPath, std::ios::binary);
  if(!f) return "";
  std::string data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  auto d = sha256stub(data);
  std::string hex;
  for(auto b: d.bytes){ char buf[3]; snprintf(buf,sizeof(buf),"%02x", b); hex+=buf; }
  // return uppercase without colons
  for(char &c: hex) c = std::toupper(c);
  return hex;
}

struct AsioTlsTransport::Impl {
  asio::io_context ioctx;
  std::unique_ptr<tcp::socket> socket;
  std::vector<uint8_t> rxBuf;
};

AsioTlsTransport::AsioTlsTransport(TrustConfig cfg): pimpl_(std::make_unique<Impl>()), cfg_(std::move(cfg)) {}
AsioTlsTransport::AsioTlsTransport(TrustConfig cfg, asio::ip::tcp::socket&& sock): pimpl_(std::make_unique<Impl>()), cfg_(std::move(cfg)) {
  pimpl_->socket = std::make_unique<tcp::socket>(std::move(sock));
}
AsioTlsTransport::~AsioTlsTransport(){ close(); }
bool AsioTlsTransport::verifyFingerprint() const {
  if(cfg_.fingerprint.empty()) return true; // no pin required
  if(cfg_.certPath.empty() && cfg_.caPath.empty()) return false;
  std::string path = !cfg_.certPath.empty() ? cfg_.certPath : cfg_.caPath;
  std::string actual = computeSha256Fingerprint(path);
  if(actual.empty()) return false;
  // compare case-insensitive hex without colons
  std::string exp = cfg_.fingerprint;
  std::string normExp, normActual;
  for(char c: exp) if(c!=':' ) normExp+= std::toupper(c);
  for(char c: actual) if(c!=':') normActual+= std::toupper(c);
  return normExp==normActual;
}
void AsioTlsTransport::connect(const std::string& host, uint16_t port){
  if(!verifyFingerprint()){
    throw TransportException("TLS fingerprint mismatch");
  }
  close();
  pimpl_ = std::make_unique<Impl>();
  tcp::resolver resolver(pimpl_->ioctx);
  auto endpoints = resolver.resolve(host, std::to_string(port));
  pimpl_->socket = std::make_unique<tcp::socket>(pimpl_->ioctx);
  asio::connect(*pimpl_->socket, endpoints);
}
void AsioTlsTransport::sendFrame(const Frame& f){
  auto wire = encodeFrame(f);
  asio::write(*pimpl_->socket, asio::buffer(wire));
}
bool AsioTlsTransport::recvFrame(Frame& out, int timeoutMs){
  (void)timeoutMs;
  while(true){
    if(pimpl_->rxBuf.size()>=4){
      uint32_t len = get32be(pimpl_->rxBuf.data());
      if(len>4u*1024u*1024u){ pimpl_->rxBuf.clear(); return false; }
      if(pimpl_->rxBuf.size()>=4+len){
        Frame tmp; tmp.type=(MsgType)pimpl_->rxBuf[4]; tmp.requestId=get32be(pimpl_->rxBuf.data()+5);
        tmp.body.assign(pimpl_->rxBuf.begin()+9, pimpl_->rxBuf.begin()+4+len);
        out=std::move(tmp);
        pimpl_->rxBuf.erase(pimpl_->rxBuf.begin(), pimpl_->rxBuf.begin()+4+len);
        return true;
      }
    }
    uint8_t buf[1024];
    asio::error_code ec;
    size_t n = pimpl_->socket->read_some(asio::buffer(buf), ec);
    if(ec) return false;
    pimpl_->rxBuf.insert(pimpl_->rxBuf.end(), buf, buf+n);
  }
}
void AsioTlsTransport::close(){
  if(pimpl_ && pimpl_->socket && pimpl_->socket->is_open()){
    asio::error_code ec; pimpl_->socket->close(ec);
  }
  if(pimpl_) pimpl_->rxBuf.clear();
}
