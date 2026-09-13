// src/domain/ids.cpp
#include "domain/ids.hpp"
#include <random>
#include <sstream>
#include <iomanip>
static std::string randomHex(size_t bytes){
  // Explicit CSPRNG: std::random_device (OS CSPRNG, BCryptGenRandom on Windows) — no mt19937
  std::random_device rd;
  std::ostringstream oss;
  for(size_t i=0;i<bytes;i++){
    unsigned int b = rd() & 0xFF;
    oss << std::hex << std::setw(2) << std::setfill('0') << b;
  }
  return oss.str();
}
UserId generateUserId(){
  std::string h = randomHex(16);
  std::string uuid = h.substr(0,8)+"-"+h.substr(8,4)+"-"+h.substr(12,4)+"-"+h.substr(16,4)+"-"+h.substr(20,12);
  return UserId{uuid};
}
SessionId generateSessionId(){
  std::string h = randomHex(32);
  return SessionId{"sess_"+h};
}
