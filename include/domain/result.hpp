// include/domain/result.hpp
#pragma once
#include <string>
#include <optional>
#include <utility>
template<typename T> struct Result {
  bool ok=false;
  std::optional<T> value{};
  std::string error;
  static Result<T> success(T v){ return {true, std::move(v), ""}; }
  static Result<T> failure(std::string e){ return {false, std::nullopt, std::move(e)}; }
};
