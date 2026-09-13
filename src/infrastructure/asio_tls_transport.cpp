#include "infrastructure/asio_tls_transport.hpp"
#include "domain/exceptions.hpp"
#include "infrastructure/sha256.hpp"
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <thread>
#include <chrono>
using asio::ip::tcp;

std::string computeSha256Fingerprint(const std::string& certPath){
  FILE* fp = fopen(certPath.c_str(), "rb");
  if(!fp) return "";
  X509* cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
  fclose(fp);
  if(!cert) {
    // fallback: try DER
    fp = fopen(certPath.c_str(), "rb");
    if(!fp) return "";
    cert = d2i_X509_fp(fp, nullptr);
    fclose(fp);
    if(!cert) return "";
  }
  unsigned char* der=nullptr;
  int len = i2d_X509(cert, &der);
  std::string hex;
  if(len>0 && der){
    unsigned char hash[32]; unsigned int outLen;
    EVP_Digest(der, len, hash, &outLen, EVP_sha256(), nullptr);
    std::ostringstream oss;
    for(unsigned i=0;i<outLen;i++) oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    hex = oss.str();
    OPENSSL_free(der);
  }
  X509_free(cert);
  for(char &c: hex) c = std::toupper(c);
  return hex;
}
static bool constantTimeEqual(const std::string& a, const std::string& b){
  if(a.size()!=b.size()) return false;
  unsigned char diff=0;
  for(size_t i=0;i<a.size();i++) diff |= a[i] ^ b[i];
  return diff==0;
}

struct AsioTlsTransport::Impl {
  asio::io_context ioctx;
  asio::ssl::context ctx{asio::ssl::context::tlsv13_client};
  std::unique_ptr<asio::ssl::stream<tcp::socket>> stream;
  std::vector<uint8_t> rxBuf;
  Impl(): ctx(asio::ssl::context::tlsv13_client) {}
  Impl(asio::ssl::context&& c): ctx(std::move(c)) {}
};

AsioTlsTransport::AsioTlsTransport(TrustConfig cfg): pimpl_(std::make_unique<Impl>()), cfg_(std::move(cfg)){
  pimpl_->ctx.set_options(asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2 | asio::ssl::context::no_tlsv1 | asio::ssl::context::no_tlsv1_1 | asio::ssl::context::no_tlsv1_2);
  pimpl_->ctx.set_verify_mode(asio::ssl::verify_peer);
  if(!cfg_.caPath.empty()){
    pimpl_->ctx.load_verify_file(cfg_.caPath);
  } else if(!cfg_.certPath.empty()){
    pimpl_->ctx.load_verify_file(cfg_.certPath);
  }
  pimpl_->ctx.set_verify_callback([this](bool preverified, asio::ssl::verify_context& ctx){
    if(!preverified) return false;
    X509* cert = X509_STORE_CTX_get0_cert(ctx.native_handle());
    if(!cert) return false;
    // check expiry
    if(X509_cmp_current_time(X509_get0_notBefore(cert)) > 0) return false;
    if(X509_cmp_current_time(X509_get0_notAfter(cert)) < 0) return false;
    if(!verifyFingerprint(cert)) return false;
    return true;
  });
}

AsioTlsTransport::AsioTlsTransport(TrustConfig cfg, asio::ssl::stream<tcp::socket>&& s): pimpl_(std::make_unique<Impl>()), cfg_(std::move(cfg)){
  // For server-accepted sockets, ctx is already configured as server
  pimpl_->stream = std::make_unique<asio::ssl::stream<tcp::socket>>(std::move(s));
}

AsioTlsTransport::~AsioTlsTransport(){ close(); }

bool AsioTlsTransport::verifyFingerprint(X509* cert) const {
  if(cfg_.fingerprint.empty()) return true;
  std::string actual = computeDerFingerprint(cert);
  if(actual.empty()) return false;
  std::string exp = cfg_.fingerprint;
  std::string normExp, normActual;
  for(char c: exp) if(c!=':') normExp+= std::toupper(c);
  for(char c: actual) if(c!=':') normActual+= std::toupper(c);
  return constantTimeEqual(normExp, normActual);
}
std::string AsioTlsTransport::computeDerFingerprint(X509* cert) const {
  unsigned char* der=nullptr;
  int len = i2d_X509(cert, &der);
  if(len<=0 || !der) return "";
  unsigned char hash[32]; unsigned int outLen;
  EVP_Digest(der, len, hash, &outLen, EVP_sha256(), nullptr);
  OPENSSL_free(der);
  std::ostringstream oss;
  for(unsigned i=0;i<outLen;i++) oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
  std::string hex = oss.str();
  for(char &c: hex) c = std::toupper(c);
  return hex;
}

void AsioTlsTransport::connect(const std::string& host, uint16_t port){
  try{
    pimpl_->stream = std::make_unique<asio::ssl::stream<tcp::socket>>(pimpl_->ioctx, pimpl_->ctx);
    tcp::resolver resolver(pimpl_->ioctx);
    auto eps = resolver.resolve(host, std::to_string(port));
    asio::connect(pimpl_->stream->lowest_layer(), eps);
    pimpl_->stream->handshake(asio::ssl::stream_base::client);
  } catch(const std::system_error& e){
    throw TransportException(std::string("TLS handshake failed: ") + e.what());
  } catch(const std::exception& e){
    throw TransportException(std::string("TLS connect failed: ") + e.what());
  }
}

void AsioTlsTransport::sendFrame(const Frame& f){
  auto wire = encodeFrame(f);
  asio::write(*pimpl_->stream, asio::buffer(wire));
}

bool AsioTlsTransport::recvFrame(Frame& out, int timeoutMs){
  (void)timeoutMs;
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
    }
    uint8_t buf[1024];
    asio::error_code ec;
    size_t n = pimpl_->stream->read_some(asio::buffer(buf), ec);
    if(ec) return false;
    if(n==0) return false;
    pimpl_->rxBuf.insert(pimpl_->rxBuf.end(), buf, buf+n);
  }
}

void AsioTlsTransport::close(){
  if(pimpl_ && pimpl_->stream){
    asio::error_code ec;
    if(pimpl_->stream->lowest_layer().is_open()){
      pimpl_->stream->lowest_layer().close(ec);
    }
  }
  if(pimpl_) pimpl_->rxBuf.clear();
}
