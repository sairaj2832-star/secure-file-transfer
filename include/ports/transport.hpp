// include/ports/transport.hpp
#pragma once
#include <cstdint>
#include <vector>
#include <string>
enum class MsgType : uint8_t { HELLO=1, AUTH=2, UPLOAD_INIT=3, DATA=4, COMMIT=5, DOWNLOAD_REQ=6, LIST=7, REVOKE=8, ERROR=255 };
struct Frame { MsgType type = MsgType::HELLO; uint32_t requestId = 0; std::vector<uint8_t> body; };
inline void put32be(std::vector<uint8_t>& v, uint32_t x) { v.push_back((x>>24)&0xFF); v.push_back((x>>16)&0xFF); v.push_back((x>>8)&0xFF); v.push_back(x&0xFF); }
inline uint32_t get32be(const uint8_t* p) { return (uint32_t(p[0])<<24)|(uint32_t(p[1])<<16)|(uint32_t(p[2])<<8)|uint32_t(p[3]); }
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