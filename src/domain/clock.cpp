// src/domain/clock.cpp
#include "domain/clock.hpp"
#include <chrono>
int64_t SystemClock::nowMs() const {
  using namespace std::chrono;
  return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}
