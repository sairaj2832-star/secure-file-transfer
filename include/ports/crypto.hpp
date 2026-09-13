// include/ports/crypto.hpp
#pragma once
#include "domain/digest.hpp"
#include "domain/wrapped_key.hpp"
#include <cstdint>
#include <vector>
struct EncryptOut { std::vector<uint8_t> cipher; WrappedKey wrapped; Digest digest; };
class IEncryptionProvider { public: virtual ~IEncryptionProvider() = default; virtual EncryptOut encrypt(const std::vector<uint8_t>& plain) = 0; virtual std::vector<uint8_t> decryptAndVerify(const std::vector<uint8_t>& cipher, const WrappedKey&, const Digest& d) = 0; };