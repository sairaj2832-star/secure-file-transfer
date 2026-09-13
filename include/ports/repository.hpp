// include/ports/repository.hpp
#pragma once
#include "domain/result.hpp"
template<typename T, typename Id>
class Repository { public: virtual ~Repository() = default; virtual void save(const T& v) = 0; virtual Result<T> find(const Id& id) const = 0; };