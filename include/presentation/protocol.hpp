// include/presentation/protocol.hpp
#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include "domain/digest.hpp"
#include "domain/wrapped_key.hpp"
struct RegisterPayload { std::string username, email, password; };
struct LoginPayload { std::string username, password; };
struct AdminPayload { std::string token; std::string targetId; };
struct UploadInit { std::string recipient, origName, uploadId; uint64_t size = 0; Digest digest{}; WrappedKey wrapped{}; };
struct UploadData { std::string uploadId; uint64_t offset = 0; std::vector<uint8_t> chunk; };
struct DownloadReq { std::string fileId; std::string token; };
std::vector<uint8_t> encodeRegister(const std::string& u, const std::string& e, const std::string& p);
RegisterPayload decodeRegister(const std::vector<uint8_t>& body);
std::vector<uint8_t> encodeLogin(const std::string& u, const std::string& p);
LoginPayload decodeLogin(const std::vector<uint8_t>& body);
std::vector<uint8_t> encodeAdmin(const std::string& token, const std::string& target);
AdminPayload decodeAdmin(const std::vector<uint8_t>& body);
std::vector<uint8_t> encodeUploadInit(const UploadInit& p);
UploadInit decodeUploadInit(const std::vector<uint8_t>& body);
std::vector<uint8_t> encodeUploadData(const UploadData& p);
UploadData decodeUploadData(const std::vector<uint8_t>& body);
std::vector<uint8_t> encodeDownloadReq(const DownloadReq& p);
DownloadReq decodeDownloadReq(const std::vector<uint8_t>& body);
