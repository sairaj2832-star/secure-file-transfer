// include/domain/permission.hpp
#pragma once
#include "domain/ids.hpp"
#include <cstdint>
struct Permission { FileId file; UserId user; int64_t expiresAt = 4102444800; bool revoked = false; };