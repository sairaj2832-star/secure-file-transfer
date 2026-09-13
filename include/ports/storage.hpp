// include/ports/storage.hpp
#pragma once
#include <cstdint>
#include <string>
#include <vector>
class IStorage { public: virtual ~IStorage() = default; virtual void write(const std::string& k, const std::vector<uint8_t>& v) = 0; virtual std::vector<uint8_t> read(const std::string& k) const = 0; };