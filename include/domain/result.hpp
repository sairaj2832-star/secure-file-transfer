// include/domain/result.hpp
#pragma once
#include <string>
template<typename T> struct Result { bool ok = false; T value{}; std::string error; };