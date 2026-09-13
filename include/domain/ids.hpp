// include/domain/ids.hpp
#pragma once
#include <string>
struct UserId { std::string value; bool operator==(const UserId&) const = default; };
struct FileId { std::string value; bool operator==(const FileId&) const = default; };
struct TransferId { std::string value; bool operator==(const TransferId&) const = default; };
struct SessionId { std::string value; bool operator==(const SessionId&) const = default; };
UserId generateUserId();
SessionId generateSessionId();
