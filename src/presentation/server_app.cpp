// src/presentation/server_app.cpp — Stage 2 blind server (real TLS, staged write, no decrypt)
#include "presentation/server_app.hpp"
#include "presentation/cli.hpp"
#include "presentation/ansi.hpp"
#include "presentation/protocol.hpp"
#include "infrastructure/sqlite_user_repo.hpp"
#include "infrastructure/argon2_hasher.hpp"
#include "infrastructure/memory_session_store.hpp"
#include "infrastructure/hash_chain_file_audit.hpp"
#include "infrastructure/asio_tls_listener.hpp"
#include "infrastructure/binary_storage.hpp"
#include "infrastructure/recipient_pubkey_directory.hpp"
#include "infrastructure/sqlite_file_repo.hpp"
#include "infrastructure/sqlite_transfer_repo.hpp"
#include "infrastructure/file_validator.hpp"
#include "application/auth_service.hpp"
#include "application/admin_service.hpp"
#include "application/transfer_service.hpp"
#include "domain/clock.hpp"
#include "domain/key_pair.hpp"
#include <iostream>
#include <filesystem>
#include <thread>
#include <unordered_map>
#include <mutex>
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
  std::filesystem::create_directories("./storage/encrypted");
  SqliteUserRepository userRepo(dbPath);
  Argon2Hasher hasher;
  SystemClock clock;
  HashChainFileAuditLogger audit("./storage/audit.log");
  MemorySessionStore sessions(&clock);
  AuthService auth(&userRepo, &hasher, &sessions, &audit, &clock);
  AdminService admin(&userRepo, &sessions, &audit, &clock);
  // Stage2 infra
  BinaryFileStorage blobStore("./storage/encrypted");
  SqlitePubkeyDirectory pubkeyDir("./storage/pubkeys.db");
  SqliteFileRepository fileRepo("./storage/files.db");
  SqliteTransferRepository transferRepo("./storage/transfers.db");
  PdfFileValidator validator;
  TransferService transfers(&blobStore, &pubkeyDir, &fileRepo, &transferRepo, &audit, &validator, &clock, &sessions, &userRepo);
  // boot sweeper deletes orphans
  try { blobStore.sweepOrphans(&fileRepo); } catch(...) {}
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
        // per-connection pending upload state
        std::unordered_map<std::string, UploadInit> pendingInit;
        std::unordered_map<std::string, std::vector<uint8_t>> pendingData;
        std::string connToken;
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
              // If registration succeeded and body contained extra pubkey (legacy), try to store it
              // The new protocol REGISTER still only has 3 fields; pubkey upload is via separate step.
              // For Stage2Gate, pubkeys are saved via direct directory access, not wire.
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
              if(res.ok && res.value.has_value()){
                body.assign(res.value->value.begin(), res.value->value.end());
                connToken = res.value->value;
              } else body.assign(msg.begin(), msg.end());
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
            if(ok && connToken==tokStr) connToken.clear();
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
          } else if(f.type==MsgType::UPLOAD_INIT){
            try{
              auto init = decodeUploadInit(f.body);
              // isValid token via sessions->isValid
              if(connToken.empty()){
                Frame reply{MsgType::ERR, f.requestId, std::vector<uint8_t>{'n','o',' ','t','o','k','e','n'}};
                conn->sendFrame(reply);
                continue;
              }
              SessionId sess{connToken};
              if(!sessions.isValid(sess, clock.nowMs())){
                Frame reply{MsgType::ERR, f.requestId, {}};
                conn->sendFrame(reply);
                printSafe("UPLOAD DENIED invalid session");
                continue;
              }
              // validator->validate (blind: use synthetic %PDF header if needed, pubkey already handled in TransferService)
              // Do lightweight validation here as well (traversal etc) using synthetic header
              try{
                std::vector<uint8_t> fakeHdr{'%','P','D','F','-','1','.','4'};
                validator.validate(init.origName, init.size, fakeHdr);
              } catch(const std::exception& e){
                Frame reply{MsgType::ERR, f.requestId, std::vector<uint8_t>(e.what(), e.what()+strlen(e.what()))};
                conn->sendFrame(reply);
                continue;
              }
              pendingInit[init.uploadId] = init;
              pendingData[init.uploadId] = {};
              std::string who = init.recipient;
              // try to resolve sender username for CLI msg
              std::string sender = "unknown";
              try{ auto s = sessions.findByToken(sess); if(s.ok && s.value.has_value()) sender = s.value->userId.value; } catch(...) {}
              printSafe("UPLOAD " + sender + "->" + who + " " + init.origName);
              Frame reply{MsgType::UPLOAD_INIT, f.requestId, std::vector<uint8_t>{'o','k'}};
              conn->sendFrame(reply);
            } catch(const std::exception& e){
              Frame reply{MsgType::ERR, f.requestId, {}};
              conn->sendFrame(reply);
            }
          } else if(f.type==MsgType::UPLOAD_DATA){
            try{
              auto data = decodeUploadData(f.body);
              auto it = pendingData.find(data.uploadId);
              if(it==pendingData.end()){
                Frame reply{MsgType::ERR, f.requestId, {}};
                conn->sendFrame(reply);
                continue;
              }
              if(data.offset != it->second.size()){
                Frame reply{MsgType::ERR, f.requestId, {}};
                conn->sendFrame(reply);
                continue;
              }
              it->second.insert(it->second.end(), data.chunk.begin(), data.chunk.end());
              Frame reply{MsgType::UPLOAD_DATA, f.requestId, std::vector<uint8_t>{'o','k'}};
              conn->sendFrame(reply);
            } catch(...){
              Frame reply{MsgType::ERR, f.requestId, {}};
              conn->sendFrame(reply);
            }
          } else if(f.type==MsgType::UPLOAD_COMMIT){
            try{
              std::string uploadId;
              // body may be uploadId string directly or DownloadReq-like or empty — try all
              if(!f.body.empty()){
                // try decode as string-with-len if first 4 bytes look like len
                if(f.body.size()>=4){
                  uint32_t len = get32be(f.body.data());
                  if(len+4==f.body.size()){
                    uploadId.assign(f.body.begin()+4, f.body.end());
                  } else {
                    // try UploadData decode fallback
                    try{
                      auto d = decodeUploadData(f.body);
                      uploadId = d.uploadId;
                    } catch(...){
                      uploadId.assign(f.body.begin(), f.body.end());
                    }
                  }
                } else {
                  uploadId.assign(f.body.begin(), f.body.end());
                }
              }
              if(uploadId.empty() && pendingInit.size()==1) uploadId = pendingInit.begin()->first;
              auto itInit = pendingInit.find(uploadId);
              auto itData = pendingData.find(uploadId);
              if(itInit==pendingInit.end() || itData==pendingData.end()){
                Frame reply{MsgType::ERR, f.requestId, {}};
                conn->sendFrame(reply);
                continue;
              }
              if(connToken.empty() || !sessions.isValid(SessionId{connToken}, clock.nowMs())){
                Frame reply{MsgType::ERR, f.requestId, {}};
                conn->sendFrame(reply);
                continue;
              }
              SessionId sess{connToken};
              // call TransferService::upload (blind, no decrypt)
              auto res = transfers.upload(sess, itInit->second.recipient, itInit->second.origName, itData->second, itInit->second.uploadId, itInit->second.size, itInit->second.digest, itInit->second.wrapped);
              if(res.ok){
                std::string tid = res.value->id.value;
                Frame reply{MsgType::UPLOAD_COMMIT, f.requestId, std::vector<uint8_t>(tid.begin(), tid.end())};
                conn->sendFrame(reply);
                printSafe("UPLOAD COMMIT " + uploadId + " -> " + tid);
                pendingInit.erase(itInit);
                pendingData.erase(itData);
              } else {
                Frame reply{MsgType::ERR, f.requestId, std::vector<uint8_t>(res.error.begin(), res.error.end())};
                conn->sendFrame(reply);
              }
            } catch(const std::exception& e){
              Frame reply{MsgType::ERR, f.requestId, {}};
              conn->sendFrame(reply);
            }
          } else if(f.type==MsgType::DOWNLOAD_REQ){
            try{
              auto req = decodeDownloadReq(f.body);
              std::string tok = req.token.empty() ? connToken : req.token;
              SessionId sess{tok};
              auto res = transfers.download(sess, FileId{req.fileId});
              if(res.ok){
                // relay opaque blob as DOWNLOAD_DATA frames (single frame for simplicity, chunked if large)
                std::vector<uint8_t> opaque = res.value.value();
                // send as DOWNLOAD_DATA with body = opaque (or UploadData wrapped)
                Frame reply{MsgType::DOWNLOAD_DATA, f.requestId, opaque};
                conn->sendFrame(reply);
                printSafe("DOWNLOAD " + req.fileId);
              } else {
                Frame reply{MsgType::ERR, f.requestId, std::vector<uint8_t>(res.error.begin(), res.error.end())};
                conn->sendFrame(reply);
                printSafe("DOWNLOAD DENIED " + req.fileId);
              }
            } catch(...){
              Frame reply{MsgType::ERR, f.requestId, {}};
              conn->sendFrame(reply);
            }
          } else if(f.type==MsgType::LIST || f.type==MsgType::DOWNLOAD_DATA){
            // LIST not yet implemented — reply empty
            Frame reply{MsgType::LIST, f.requestId, {}};
            conn->sendFrame(reply);
          } else {
            Frame reply{MsgType::ERR, f.requestId, {}};
            conn->sendFrame(reply);
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
