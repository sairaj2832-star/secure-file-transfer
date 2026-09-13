#include "infrastructure/hash_chain_file_audit.hpp"
#include "domain/digest.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
HashChainFileAuditLogger::HashChainFileAuditLogger(const std::string& path): path_(path){
  std::ifstream f(path_);
  if(f){
    std::string line;
    while(std::getline(f,line)){
      // find msgHash field
      auto pos = line.find("\"msgHash\":\"");
      if(pos!=std::string::npos){
        pos+=11;
        auto end=line.find("\"",pos);
        if(end!=std::string::npos) lastHash_=line.substr(pos,end-pos);
      }
    }
  }
}
std::string HashChainFileAuditLogger::sha256hex(const std::string& s) const {
  auto d = sha256stub(s);
  std::string hex;
  for(auto b: d.bytes){ char buf[3]; snprintf(buf,sizeof(buf),"%02x", b); hex+=buf; }
  return hex;
}
std::string HashChainFileAuditLogger::canonical(const AuditEvent& e) const {
  std::ostringstream oss;
  oss << "{\"seq\":"<<e.seq<<",\"ts\":\""<<e.ts<<"\",\"actor\":\""<<e.actor<<"\",\"action\":\""<<e.action<<"\",\"fileId\":\""<<e.fileId<<"\",\"cipherHash\":\""<<e.cipherHash<<"\",\"prevHash\":\""<<e.prevHash<<"\"}";
  return oss.str();
}
void HashChainFileAuditLogger::record(AuditEvent e){
  e.prevHash = lastHash_;
  std::string can = canonical(e);
  e.msgHash = sha256hex(can);
  e.seq = 0; // seq not used for file, but set
  // append
  std::ofstream out(path_, std::ios::app);
  out << "{\"seq\":"<<e.seq<<",\"ts\":\""<<e.ts<<"\",\"actor\":\""<<e.actor<<"\",\"action\":\""<<e.action<<"\",\"fileId\":\""<<e.fileId<<"\",\"cipherHash\":\""<<e.cipherHash<<"\",\"prevHash\":\""<<e.prevHash<<"\",\"msgHash\":\""<<e.msgHash<<"\"}\n";
  out.flush();
  lastHash_ = e.msgHash;
}
std::vector<AuditEvent> HashChainFileAuditLogger::all() const {
  std::vector<AuditEvent> out;
  std::ifstream f(path_);
  std::string line;
  while(std::getline(f,line)){
    AuditEvent e;
    // minimal parse: extract action and actor for tests, but full parse not needed
    auto getField=[&](const std::string& key){
      std::string pat="\""+key+"\":\"";
      auto p=line.find(pat);
      if(p==std::string::npos) return std::string();
      p+=pat.size();
      auto q=line.find("\"",p);
      return line.substr(p,q-p);
    };
    e.action=getField("action");
    e.actor=getField("actor");
    e.fileId=getField("fileId");
    e.prevHash=getField("prevHash");
    e.msgHash=getField("msgHash");
    e.ts=getField("ts");
    out.push_back(e);
  }
  return out;
}
bool HashChainFileAuditLogger::verify() const {
  std::ifstream f(path_);
  std::string line;
  std::string prev="GENESIS";
  while(std::getline(f,line)){
    std::string storedPrev, storedHash, ts, actor, action, fileId, cipherHash;
    auto get=[&](const std::string& k){
      std::string pat="\""+k+"\":\"";
      auto p=line.find(pat);
      if(p==std::string::npos) return std::string();
      p+=pat.size();
      auto q=line.find("\"",p);
      return line.substr(p,q-p);
    };
    std::string seqStr=get("seq");
    ts=get("ts"); actor=get("actor"); action=get("action"); fileId=get("fileId"); cipherHash=get("cipherHash");
    storedPrev=get("prevHash"); storedHash=get("msgHash");
    if(storedPrev!=prev) return false;
    AuditEvent e{0,ts,actor,action,fileId,cipherHash,prev,""};
    std::string can = canonical(e);
    std::string recomputed = sha256hex(can);
    if(recomputed!=storedHash) return false;
    prev=storedHash;
  }
  return true;
}
void HashChainFileAuditLogger::close(){}
