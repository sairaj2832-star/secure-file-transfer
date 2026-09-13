// include/ports/policy.hpp
#pragma once
#include "domain/ids.hpp"
#include "domain/file_record.hpp"
class IAccessPolicy { public: virtual ~IAccessPolicy() = default; virtual bool isAuthorized(const UserId& u, const FileRecord& f) const = 0; };