// src/domain/ids.cpp
#include "domain/ids.hpp"
#include <random>
#include <sstream>
#include <iomanip>
static std::string randomHex(size_t bytes){
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<int> dis(0,255);
  std::ostringstream oss;
  for(size_t i=0;i<bytes;i++){
    oss << std::hex << std::setw(2) << std::setfill('0') << dis(gen);
  }
  return oss.str();
}
UserId generateUserId(){
  // 16 bytes = 32 hex chars, format as UUID-like
  std::string h = randomHex(16);
  std::string uuid = h.substr(0,8)+"-"+h.substr(8,4)+"-"+h.substr(12,4)+"-"+h.substr(16,4)+"-"+h.substr(20,12);
  return UserId{uuid};
}
SessionId generateSessionId(){
  // 32 bytes base -> hex, prefixed dl_
  std::string h = randomHex(32);
  return SessionId{"dl_"+h};
}
