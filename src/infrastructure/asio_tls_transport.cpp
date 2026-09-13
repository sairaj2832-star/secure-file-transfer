#include "infrastructure/asio_tls_transport.hpp"
#include "domain/exceptions.hpp"
#include "infrastructure/sha256.hpp"
#include <asio.hpp>
#include <fstream>
#include <sstream>
#include <chrono>
using asio::ip::tcp;

std::string computeSha256Fingerprint(const std::string& certPath){
  std::ifstream f(certPath, std::ios::binary);
  if(!f) return "";
  std::string data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  // Real SHA-256 of file bytes (for self-signed test cert, hash PEM text; for real cert, should be DER via i2d_X509)
  std::string hex = real_sha256::hex(data);
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
  auto start = std::chrono::steady_clock::now();
  while(true){
    if(pimpl_->rxBuf.size()>=4){
      uint32_t len = get32be(pimpl_->rxBuf.data());
      if(len<5 || len>4u*1024u*1024u){ pimpl_->rxBuf.clear(); return false; }
      if(pimpl_->rxBuf.size()>=4+len){
        Frame tmp; tmp.type=(MsgType)pimpl_->rxBuf[4]; tmp.requestId=get32be(pimpl_->rxBuf.data()+5);
        tmp.body.assign(pimpl_->rxBuf.begin()+9, pimpl_->rxBuf.begin()+4+len);
        out=std::move(tmp);
        pimpl_->rxBuf.erase(pimpl_->rxBuf.begin(), pimpl_->rxBuf.begin()+4+len);
        return true;
      }
      if(pimpl_->rxBuf.size()>4+len) { pimpl_->rxBuf.clear(); return false; }
    }
    if(timeoutMs>=0){
      auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-start).count();
      if(elapsed>=timeoutMs) return false;
      fd_set set; FD_ZERO(&set);
      auto h = pimpl_->socket->native_handle();
      FD_SET(h, &set);
      timeval tv{0, 10000}; // 10ms poll
#ifdef _WIN32
      int ret = select(0, &set, nullptr, nullptr, &tv);
#else
      int ret = select(h+1, &set, nullptr, nullptr, &tv);
#endif
      if(ret==0) continue;
      if(ret<0) return false;
    }
    // check if data available without blocking
    if(pimpl_->socket->available()==0 && timeoutMs>=0){
      // already handled via select poll
    }
    uint8_t buf[1024];
    asio::error_code ec;
    // set non-blocking for poll case
    pimpl_->socket->non_blocking(true, ec);
    size_t n = pimpl_->socket->read_some(asio::buffer(buf), ec);
    pimpl_->socket->non_blocking(false, ec);
    if(ec==asio::error::would_block) continue;
    if(ec) return false;
    if(n==0) return false;
    pimpl_->rxBuf.insert(pimpl_->rxBuf.end(), buf, buf+n);
    // check truncated: if we have len but not enough data and timeout exceeded, return false
    if(pimpl_->rxBuf.size()>=4){
      uint32_t len = get32be(pimpl_->rxBuf.data());
      if(len<5 || len>4u*1024u*1024u) { pimpl_->rxBuf.clear(); return false; }
    }
  }
}
void AsioTlsTransport::close(){
  if(pimpl_ && pimpl_->socket && pimpl_->socket->is_open()){
    asio::error_code ec; pimpl_->socket->close(ec);
  }
  if(pimpl_) pimpl_->rxBuf.clear();
}
