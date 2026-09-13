#include "infrastructure/hash_chain_file_audit.hpp"
#include "infrastructure/sha256.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif
static std::string jsonEscape(const std::string& s){
  std::string out;
  for(char c: s){
    if(c=='"') out+="\\\"";
    else if(c=='\\') out+="\\\\";
    else if(c=='\n') out+="\\n";
    else if(c=='\r') out+="\\r";
    else if(c=='\t') out+="\\t";
    else if((unsigned char)c<0x20){
      char buf[7]; snprintf(buf,sizeof(buf),"\\u%04x",(unsigned char)c);
      out+=buf;
    } else out+=c;
  }
  return out;
}
HashChainFileAuditLogger::HashChainFileAuditLogger(const std::string& path): path_(path){
  // startup verification: if file exists and is not empty, verify chain; if corrupted, refuse to append
  std::ifstream f(path_);
  if(f){
    std::string line;
    bool hasContent=false;
    while(std::getline(f,line)) hasContent=true;
    if(hasContent){
      if(!verify()){
        // mark as corrupted — record() will throw
        lastHash_ = "CORRUPTED";
        return;
      }
      // set lastHash and lastSeq from last line
      f.clear(); f.seekg(0);
      std::string lastLine;
      while(std::getline(f,line)) lastLine=line;
      auto get=[&](const std::string& k, const std::string& l){
        std::string pat="\""+k+"\":";
        auto p=l.find(pat);
        if(p==std::string::npos) return std::string();
        p+=pat.size();
        if(l[p]=='"'){ p++; auto q=l.find("\"",p); return l.substr(p,q-p); }
        else { auto q=l.find(",",p); if(q==std::string::npos) q=l.find("}",p); return l.substr(p,q-p); }
      };
      lastHash_=get("msgHash", lastLine);
      std::string seqStr=get("seq", lastLine);
      try{ lastSeq_ = std::stoull(seqStr); } catch(...){ lastSeq_=0; }
    }
  }
  if(lastHash_.empty()) lastHash_="GENESIS";
}
std::string HashChainFileAuditLogger::sha256hex(const std::string& s) const {
  return real_sha256::hex(s);
}
std::string HashChainFileAuditLogger::canonical(const AuditEvent& e) const {
  std::ostringstream oss;
  oss << "{\"seq\":"<<e.seq<<",\"ts\":\""<<jsonEscape(e.ts)<<"\",\"actor\":\""<<jsonEscape(e.actor)<<"\",\"action\":\""<<jsonEscape(e.action)<<"\",\"fileId\":\""<<jsonEscape(e.fileId)<<"\",\"cipherHash\":\""<<jsonEscape(e.cipherHash)<<"\",\"prevHash\":\""<<jsonEscape(e.prevHash)<<"\"}";
  return oss.str();
}
void HashChainFileAuditLogger::record(AuditEvent e){
  if(lastHash_=="CORRUPTED") throw std::runtime_error("audit chain corrupted — refuse to append");
  if(!verify()) throw std::runtime_error("audit chain verification failed before append");
  e.prevHash = lastHash_;
  e.seq = ++lastSeq_;
  if(e.ts.empty()){
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm gm = *std::gmtime(&t);
    char buf[32]; std::strftime(buf,sizeof(buf),"%Y-%m-%dT%H:%M:%SZ",&gm);
    e.ts = buf;
  }
  std::string can = canonical(e);
  e.msgHash = sha256hex(can);
  std::ofstream out(path_, std::ios::app);
  out << "{\"seq\":"<<e.seq<<",\"ts\":\""<<jsonEscape(e.ts)<<"\",\"actor\":\""<<jsonEscape(e.actor)<<"\",\"action\":\""<<jsonEscape(e.action)<<"\",\"fileId\":\""<<jsonEscape(e.fileId)<<"\",\"cipherHash\":\""<<jsonEscape(e.cipherHash)<<"\",\"prevHash\":\""<<jsonEscape(e.prevHash)<<"\",\"msgHash\":\""<<e.msgHash<<"\"}\n";
  out.flush();
  out.close();
#ifdef _WIN32
  HANDLE h = CreateFileA(path_.c_str(), GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if(h!=INVALID_HANDLE_VALUE){ FlushFileBuffers(h); CloseHandle(h); }
  // fsync directory
  std::string dir = path_.substr(0, path_.find_last_of("/\\"));
  if(!dir.empty()){
    HANDLE dh = CreateFileA(dir.c_str(), GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if(dh!=INVALID_HANDLE_VALUE){ FlushFileBuffers(dh); CloseHandle(dh); }
  }
#else
  int fd = fileno(out.rdbuf());
  if(fd!=-1) fsync(fd);
#endif
  lastHash_ = e.msgHash;
}
std::vector<AuditEvent> HashChainFileAuditLogger::all() const {
  std::vector<AuditEvent> out;
  std::ifstream f(path_);
  std::string line;
  while(std::getline(f,line)){
    AuditEvent e;
    auto getField=[&](const std::string& key){
      std::string pat="\""+key+"\":";
      auto p=line.find(pat);
      if(p==std::string::npos) return std::string();
      p+=pat.size();
      if(line[p]=='"'){ p++; auto q=line.find("\"",p); // handle escaped quotes naively for test
        // find closing quote not preceded by backslash
        while(q!=std::string::npos && line[q-1]=='\\') q=line.find("\"",q+1);
        return line.substr(p,q-p);
      } else {
        auto q=line.find(",",p);
        if(q==std::string::npos) q=line.find("}",p);
        return line.substr(p,q-p);
      }
    };
    e.action=getField("action");
    e.actor=getField("actor");
    e.fileId=getField("fileId");
    e.prevHash=getField("prevHash");
    e.msgHash=getField("msgHash");
    e.ts=getField("ts");
    std::string seqStr=getField("seq");
    try{ e.seq=std::stoull(seqStr); } catch(...){ e.seq=0; }
    out.push_back(e);
  }
  return out;
}
bool HashChainFileAuditLogger::verify() const {
  std::ifstream f(path_);
  if(!f) return true; // missing file is not corrupted, just empty
  std::string line;
  std::string prev="GENESIS";
  uint64_t expectedSeq=1;
  bool hasContent=false;
  while(std::getline(f,line)){
    if(line.empty()) continue;
    hasContent=true;
    auto get=[&](const std::string& k){
      std::string pat="\""+k+"\":";
      auto p=line.find(pat);
      if(p==std::string::npos) return std::string();
      p+=pat.size();
      if(line[p]=='"'){ p++; auto q=line.find("\"",p);
        while(q!=std::string::npos && line[q-1]=='\\') q=line.find("\"",q+1);
        return line.substr(p,q-p);
      } else {
        auto q=line.find(",",p);
        if(q==std::string::npos) q=line.find("}",p);
        return line.substr(p,q-p);
      }
    };
    std::string seqStr=get("seq");
    uint64_t seq=0; try{ seq=std::stoull(seqStr);}catch(...){}
    if(seq!=expectedSeq) return false;
    std::string ts=get("ts"), actor=get("actor"), action=get("action"), fileId=get("fileId"), cipherHash=get("cipherHash");
    std::string storedPrev=get("prevHash"), storedHash=get("msgHash");
    if(storedPrev!=prev) return false;
    AuditEvent e{seq,ts,actor,action,fileId,cipherHash,prev,""};
    std::string can = canonical(e);
    std::string recomputed = sha256hex(can);
    if(recomputed!=storedHash) return false;
    prev=storedHash;
    expectedSeq++;
  }
  if(!hasContent) return true;
  return true;
}
void HashChainFileAuditLogger::close(){}
