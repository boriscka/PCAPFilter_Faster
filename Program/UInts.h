#ifndef UINTS_H
#define UINTS_H

#include <stdint.h>
#include <sstream>

#include "FilterDefines.h"

inline uint16_t Swap16(uint16_t U16)
{
  union union16
  {
    uint16_t d16;
    char d8[2];
  } src, dsn;
  src.d16 = U16;
  dsn.d8[0] = src.d8[1],
    dsn.d8[1] = src.d8[0];
  return dsn.d16;
}

inline uint32_t Swap32(uint32_t U32)
{
  union union32
  {
    uint32_t d32;
    char d8[4];
  } src, dsn;
  src.d32 = U32;
  dsn.d8[0] = src.d8[3],
    dsn.d8[1] = src.d8[2],
    dsn.d8[2] = src.d8[1],
    dsn.d8[3] = src.d8[0];
  return dsn.d32;
}

inline uint64_t Swap64(uint64_t U64)
{
  union union64
  {
    uint64_t d64;
    char d8[8];
  } src, dsn;
  src.d64 = U64;
  dsn.d8[0] = src.d8[7],
    dsn.d8[1] = src.d8[6],
    dsn.d8[2] = src.d8[5],
    dsn.d8[3] = src.d8[4],
    dsn.d8[4] = src.d8[3],
    dsn.d8[5] = src.d8[2],
    dsn.d8[6] = src.d8[1],
    dsn.d8[7] = src.d8[0];
  return dsn.d64;
}

PACK_STRUCT_START

constexpr auto INT128_BYTES = 16;
struct uint128_t {
  uint128_t() {}
  uint128_t(const uint64_t& halfOne, const uint64_t& halfTwo) {
    for (size_t i = 0; i < INT128_BYTES; ++i) {
      if (i < (INT128_BYTES >> 1)) {
        num[i] = *(reinterpret_cast<const uint8_t*>(&halfOne) + i);
      }
      else {
        num[i] = *(reinterpret_cast<const uint8_t*>(&halfTwo) + i - (INT128_BYTES >> 1));
      }
    }
  }
  uint128_t(const uint128_t& copy) {
    const uint8_t* otherNUm = copy.getNum();
    for (size_t i = 0; i < INT128_BYTES; ++i) {
      num[i] = otherNUm[i];
    }
  }
  uint128_t(const uint64_t& numb) {
    *this = numb;
  }
  uint128_t(int numb) {
    *this = static_cast<uint64_t>(numb);
  }

  uint128_t& operator=(const uint64_t& number) {
    for (size_t i = 0; i < INT128_BYTES; ++i) {
      uint64_t tmp64 = number;
      num[i] = i < 8 ? 0 : *(reinterpret_cast<const uint8_t*>(&number) + i - 8);
    }
    return *this;
  }
  uint128_t& operator=(const uint128_t& copy) {
    const uint8_t* otherNUm = copy.getNum();
    for (size_t i = 0; i < INT128_BYTES; ++i) {
      num[i] = otherNUm[i];
    }
    return *this;
  }
  uint128_t& operator=(int number) {
    *this = static_cast<uint64_t>(number);
    return *this;
  }
  uint128_t& operator=(const uint8_t* ptr) {
    *this = uint128_t(*reinterpret_cast<const uint64_t*>(ptr), *reinterpret_cast<const uint64_t*>(ptr + 8));
    return *this;
  }

  bool operator<(const uint128_t& other) const
  {
    const uint8_t* otherNUm = other.getNum();
    for (size_t i = 0; i < INT128_BYTES; ++i) {
      if (num[i] != otherNUm[i]) return num[i] < otherNUm[i];
      if (i == (INT128_BYTES - 1) && num[i] == otherNUm[i]) {
        return true;
      }
    }
    return false;
  }

  bool operator==(const uint128_t& other) const
  {
    const uint8_t* otherNUm = other.getNum();
    for (size_t i = 0; i < INT128_BYTES; ++i) {
      if (num[i] != otherNUm[i]) return false;
    }
    return true;
  }
  bool operator==(const uint64_t& number) const
  {
    return *this == uint128_t(number);
  }
  bool operator==(const int& number) const
  {
    return *this == uint128_t(number);
  }

  bool operator!=(const uint128_t& other) const
  {
    return !(*this == other);
  }
  bool operator!=(int number) const
  {
    return *this != uint128_t(number);
  }

  operator bool() const {
    return *this != uint128_t(0);
  }

  const uint8_t* getNum() const { return num; }

  std::string toString() const { 
    std::stringstream str;
    str << std::hex;
    for (int i = INT128_BYTES - 1; i >= 0; --i) {
      str << (unsigned int)(num[i]);
    }
    return str.str(); 
  }

private:
  uint8_t num[INT128_BYTES];
};

PACK_STRUCT_END

#endif // UINTS_H
