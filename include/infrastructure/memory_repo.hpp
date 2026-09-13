// include/infrastructure/memory_repo.hpp
#pragma once
#include "ports/repository.hpp"
#include <unordered_map>
template<typename T, typename Id, typename KeyFn>
class InMemoryRepo : public Repository<T, Id> {
 public:
  explicit InMemoryRepo(KeyFn k) : key_(k) {}
  void save(const T& v) override { m_[key_(v)] = v; }
  Result<T> find(const Id& id) const override {
    auto it = m_.find(id.value);
    if (it == m_.end()) return {false, T{}, "not found"};
    return {true, it->second, ""};
  }
 private:
  KeyFn key_; std::unordered_map<std::string, T> m_;
};