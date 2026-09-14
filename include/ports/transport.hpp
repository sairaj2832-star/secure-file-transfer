// include/ports/transport.hpp
#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <stdexcept>
enum class MsgType : uint8_t { HELLO=1, AUTH=2, REGISTER=3, LOGOUT=4, ADMIN_ACTIVATE=5, ADMIN_DEACTIVATE=6, UPLOAD_INIT=7, UPLOAD_DATA=8, UPLOAD_COMMIT=9, DOWNLOAD_REQ=10, DOWNLOAD_DATA=11, LIST=12, ERR=255, DATA=UPLOAD_DATA, COMMIT=UPLOAD_COMMIT, REVOKE=LIST };
struct Frame { MsgType type = MsgType::HELLO; uint32_t requestId = 0; std::vector<uint8_t> body; };
inline void put32be(std::vector<uint8_t>& v, uint32_t x) { v.push_back((x>>24)&0xFF); v.push_back((x>>16)&0xFF); v.push_back((x>>8)&0xFF); v.push_back(x&0xFF); }
inline uint32_t get32be(const uint8_t* p) { return (uint32_t(p[0])<<24)|(uint32_t(p[1])<<16)|(uint32_t(p[2])<<8)|uint32_t(p[3]); }
inline void put64be(std::vector<uint8_t>& v, uint64_t x) { for(int i=7;i>=0;--i) v.push_back(uint8_t((x >> (i*8)) & 0xFF)); }
inline uint64_t get64be(const uint8_t* p) { uint64_t v=0; for(int i=0;i<8;++i) v = (v<<8) | uint64_t(p[i]); return v; }
inline void putBytesWithLen(std::vector<uint8_t>& v, const std::vector<uint8_t>& b) { put32be(v, (uint32_t)b.size()); v.insert(v.end(), b.begin(), b.end()); }
inline std::vector<uint8_t> getBytesWithLen(const std::vector<uint8_t>& buf, size_t& off) {
  if(off+4 > buf.size()) throw std::runtime_error("short");
  uint32_t len = get32be(buf.data()+off); off+=4;
  if(off+len > buf.size()) throw std::runtime_error("short body");
  std::vector<uint8_t> out(buf.begin()+off, buf.begin()+off+len); off+=len; return out;
}
inline void putStringWithLen(std::vector<uint8_t>& v, const std::string& s) { put32be(v, (uint32_t)s.size()); v.insert(v.end(), s.begin(), s.end()); }
inline std::string getStringWithLen(const std::vector<uint8_t>& buf, size_t& off) {
  if(off+4 > buf.size()) throw std::runtime_error("short");
  uint32_t len = get32be(buf.data()+off); off+=4;
  if(off+len > buf.size()) throw std::runtime_error("short body");
  std::string s(buf.begin()+off, buf.begin()+off+len); off+=len; return s;
}
inline std::vector<uint8_t> encodeFrame(const Frame& f) {
  std::vector<uint8_t> payload; payload.push_back((uint8_t)f.type); put32be(payload, f.requestId);
  payload.insert(payload.end(), f.body.begin(), f.body.end());
  std::vector<uint8_t> wire; put32be(wire, (uint32_t)payload.size()); wire.insert(wire.end(), payload.begin(), payload.end());
  return wire;
}
inline bool tryDecode(const std::vector<uint8_t>& buf, Frame& out, size_t& consumed) {
  if (buf.size() < 4) return false;
  uint32_t len = get32be(buf.data());
  if (len > 4u*1024u*1024u) return false;
  if (buf.size() < 4 + len || len < 5) return false;
  out.type = (MsgType)buf[4]; out.requestId = get32be(buf.data()+5);
  out.body.assign(buf.begin()+9, buf.begin()+4+len);
  consumed = 4 + len;
  return true;
}
class ITransport { public: virtual ~ITransport() = default; virtual void connect(const std::string&, uint16_t) = 0; virtual void sendFrame(const Frame&) = 0; virtual bool recvFrame(Frame&, int) = 0; virtual void close() = 0; };