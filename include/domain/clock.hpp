// include/domain/clock.hpp
#pragma once
#include <cstdint>
class IClock { public: virtual ~IClock()=default; virtual int64_t nowMs() const = 0; };
class SystemClock : public IClock { public: int64_t nowMs() const override; };
class FakeClock : public IClock { public: explicit FakeClock(int64_t t=0): t_(t) {} int64_t nowMs() const override { return t_; } void advance(int64_t d){ t_+=d; } void set(int64_t t){ t_=t; } private: int64_t t_; };
