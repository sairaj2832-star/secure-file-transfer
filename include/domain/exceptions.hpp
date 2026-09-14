// include/domain/exceptions.hpp
#pragma once
#include <stdexcept>
#include <string>
struct AppException : std::runtime_error { using std::runtime_error::runtime_error; };
struct ValidationException : AppException { using AppException::AppException; };
struct AuthException : AppException { using AppException::AppException; };
struct NotFoundException : AppException { using AppException::AppException; };
struct StorageException : AppException { using AppException::AppException; };
struct IntegrityException : AppException { using AppException::AppException; };
struct TransportException : AppException { using AppException::AppException; };