// src/presentation/server_app.cpp — Stage 1 real server (Argon2/SQLite/HashChain/TLS)
#include "presentation/server_app.hpp"
#include "presentation/cli.hpp"
#include "presentation/ansi.hpp"
#include "presentation/protocol.hpp"
#include "infrastructure/sqlite_user_repo.hpp"
#include "infrastructure/argon2_hasher.hpp"
#include "infrastructure/memory_session_store.hpp"
#include "infrastructure/hash_chain_file_audit.hpp"
#include "infrastructure/asio_tls_listener.hpp"
#include "application/auth_service.hpp"
#include "application/admin_service.hpp"
#include "domain/clock.hpp"
#include <iostream>
#include <filesystem>
#include <thread>
int ServerApp::run(uint16_t port) {
  TrustConfig trust;
  trust.certPath = "./certs/server.crt";
  trust.keyPath = "./certs/server.key";
  trust.caPath = "./certs/server.crt";
  std::string fp = computeSha256Fingerprint(trust.certPath);
  if(!fp.empty()) trust.fingerprint = fp;
  else trust.fingerprint = "NO-CERT-FOUND";
  std::cout << ansi::green() << "SERVER IPv4=127.0.0.1 PORT=" << port << " FINGERPRINT=" << trust.fingerprint << ansi::reset() << "\n";
  std::string dbPath = "./storage/users.db";
  std::filesystem::create_directories("./storage");
  SqliteUserRepository userRepo(dbPath);
  Argon2Hasher hasher;
  SystemClock clock;
  HashChainFileAuditLogger audit("./storage/audit.log");
  MemorySessionStore sessions(&clock);
  AuthService auth(&userRepo, &hasher, &sessions, &audit, &clock);
  AdminService admin(&userRepo, &sessions, &audit, &clock);
  if(userRepo.listAll().empty()){
    std::cout << "No users — initial admin setup required.\n";
    std::cout << "Enter admin username: "; std::string u; std::getline(std::cin, u);
    std::cout << "Enter admin email: "; std::string e; std::getline(std::cin, e);
    std::cout << "Enter admin password (min 8 chars): "; std::string p; std::getline(std::cin, p);
    if(!u.empty() && !e.empty() && p.size()>=8){
      auto res = auth.registerUser(u, e, p, "admin");
      if(res.ok) printSafe(formatSafeAuthMessage(AuditAction::REGISTER_OK, u));
      else printError("Admin bootstrap failed: " + res.error);
    }
  }
  AsioTlsListener listener(trust);
  uint16_t actual = listener.listen(port);
  std::cout << "Listening on port " << actual << " with TLS 1.3 verify_peer\n";
  std::cout << "Server running — press Enter to stop (or Ctrl+C)\n";
  std::thread acceptThread([&]{
    while(true){
      try{
        auto conn = listener.accept();
        while(true){
          Frame f;
          if(!conn->recvFrame(f, 30000)) break;
          if(f.type==MsgType::REGISTER){
            try{
              auto pl = decodeRegister(f.body);
              auto res = auth.registerUser(pl.username, pl.email, pl.password);
              std::string msg = res.ok ? formatSafeAuthMessage(AuditAction::REGISTER_OK, pl.username) : formatSafeAuthMessage(AuditAction::REGISTER_FAIL, pl.username);
              Frame reply{MsgType::REGISTER, f.requestId, std::vector<uint8_t>(msg.begin(), msg.end())};
              conn->sendFrame(reply);
              printSafe(msg);
            } catch(...){
              Frame reply{MsgType::ERR, f.requestId, {}};
              conn->sendFrame(reply);
            }
          } else if(f.type==MsgType::AUTH){
            try{
              auto pl = decodeLogin(f.body);
              auto res = auth.login(pl.username, pl.password);
              std::string msg = res.ok ? formatSafeAuthMessage(AuditAction::LOGIN_OK, pl.username) : formatSafeAuthMessage(AuditAction::LOGIN_FAIL, pl.username);
              std::vector<uint8_t> body;
              if(res.ok && res.value.has_value()) body.assign(res.value->value.begin(), res.value->value.end());
              else body.assign(msg.begin(), msg.end());
              Frame reply{res.ok? MsgType::AUTH : MsgType::ERR, f.requestId, body};
              conn->sendFrame(reply);
              printSafe(msg);
            } catch(...){
              Frame reply{MsgType::ERR, f.requestId, {}};
              conn->sendFrame(reply);
            }
          } else if(f.type==MsgType::LOGOUT){
            std::string tokStr(f.body.begin(), f.body.end());
            bool ok = auth.logout(SessionId{tokStr});
            std::string msg = ok ? formatSafeAuthMessage(AuditAction::LOGOUT, "") : "Logout failed";
            Frame reply{ok? MsgType::LOGOUT : MsgType::ERR, f.requestId, std::vector<uint8_t>(msg.begin(), msg.end())};
            conn->sendFrame(reply);
            printSafe(msg);
          } else if(f.type==MsgType::ADMIN_ACTIVATE || f.type==MsgType::ADMIN_DEACTIVATE){
            try{
              auto adminPl = decodeAdmin(f.body);
              SessionId token{adminPl.token};
              UserId target{adminPl.targetId};
              Result<UserId> res = (f.type==MsgType::ADMIN_ACTIVATE) ? admin.activate(token, target) : admin.deactivate(token, target);
              std::string msg = res.ok ? (f.type==MsgType::ADMIN_ACTIVATE? formatSafeAuthMessage(AuditAction::ACTIVATE, adminPl.targetId) : formatSafeAuthMessage(AuditAction::DEACTIVATE, adminPl.targetId)) : "Admin denied";
              Frame reply{res.ok? f.type : MsgType::ERR, f.requestId, std::vector<uint8_t>(msg.begin(), msg.end())};
              conn->sendFrame(reply);
              printSafe(msg);
            } catch(...){
              Frame r{MsgType::ERR, f.requestId, {}}; conn->sendFrame(r);
            }
          }
        }
      } catch(...){}
    }
  });
  acceptThread.detach();
  std::string dummy; std::getline(std::cin, dummy);
  listener.close();
  return 0;
}
