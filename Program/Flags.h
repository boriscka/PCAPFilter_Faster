#include <stdint.h>
#include <initializer_list>

#define flugs_operator(op)\
constexpr inline Flags operator op (EnumClassBaseType f) const noexcept\
{\
  return Flags(static_cast<EnumClassBaseType>(i) op f);\
}\
constexpr inline Flags& operator op##=(EnumClassBaseType mask) noexcept\
{\
  i = static_cast<EnumClass>(static_cast<EnumClassBaseType>(i) op mask);\
  return *this;\
}\
constexpr inline Flags operator op (EnumClass mask) const noexcept\
{\
  return Flags(static_cast<EnumClassBaseType>(i) op static_cast<EnumClassBaseType>(mask));\
}\
constexpr inline Flags& operator op##=(EnumClass mask) noexcept\
{\
  i = static_cast<EnumClass>(static_cast<EnumClassBaseType>(i) op static_cast<EnumClassBaseType>(mask));\
  return *this;\
}

template<typename EnumClass, typename EnumClassBaseType>
class Flags
{
  //static_assert((sizeof(EnumClass) <= sizeof(EnumClassBaseType)),
    //                "Flags uses an int as storage, so an enum with underlying "
      //              "long long will overflow.");
  //static_assert((std::is_enum<EnumClass>::value), "Flags is only usable on enumeration types.");

  struct Private;
  typedef int(Private::*Zero);

public:

  constexpr inline Flags(EnumClass f) noexcept : i(f)
  {
  }

  constexpr inline Flags(EnumClassBaseType f) noexcept
    : i(static_cast<EnumClass>(f))
  {
  }

  constexpr inline Flags(Zero = nullptr) noexcept : i( static_cast<EnumClass>(0))
  {
  }

  constexpr inline Flags(std::initializer_list<EnumClass> flags) noexcept
    : i(initializer_list_helper(flags.begin(), flags.end()))
  {
  }

  constexpr inline bool operator!() const noexcept
  {
    return !static_cast<EnumClassBaseType>(i);
  }

  constexpr inline operator EnumClassBaseType() const noexcept
  {
    return static_cast<EnumClassBaseType>(i);
  }

  constexpr inline operator bool() const noexcept
  {
    return static_cast<EnumClassBaseType>(i) != 0;
  }

  constexpr inline Flags operator~() const noexcept
  {
    return Flags(~static_cast<EnumClassBaseType>(i));
  }

  constexpr inline bool operator<(const Flags& other) const
  {
    return static_cast<EnumClassBaseType>(i) < static_cast<EnumClassBaseType>(other.i);
  }

  constexpr inline bool operator!=(const Flags& other) const
  {
    return static_cast<EnumClassBaseType>(i) != static_cast<EnumClassBaseType>(other.i);
  }

  constexpr inline bool operator==(const Flags& other) const
  {
    return static_cast<EnumClassBaseType>(i) == static_cast<EnumClassBaseType>(other.i);
  }

  constexpr inline bool TestFlag(EnumClass f) const
  {
    return 
      (static_cast<EnumClassBaseType>(i) & static_cast<EnumClassBaseType>(f)) == static_cast<EnumClassBaseType>(f) &&
      (static_cast<EnumClassBaseType>(f) != 0 || static_cast<EnumClassBaseType>(i) == static_cast<EnumClassBaseType>(f));
  }

  constexpr inline Flags& SetFlag(EnumClass f, bool on)
  {
    return on ? (*this |= f) : (*this &= ~static_cast<EnumClassBaseType>(f));
  }

  flugs_operator(|)
  flugs_operator(&)
  flugs_operator(^)

private:

  constexpr static inline EnumClass initializer_list_helper(
    typename std::initializer_list<EnumClass>::const_iterator it,
    typename std::initializer_list<EnumClass>::const_iterator end
  ) noexcept
  {
    return (it == end ? EnumClass(0) : (EnumClass(*it) | initializer_list_helper(it + 1, end)));
  }

  EnumClass i;
};

#define Flags8(EnumType)  Flags<EnumType, uint8_t>
#define Flags16(EnumType) Flags<EnumType, uint16_t>
#define Flags32(EnumType) Flags<EnumType, uint32_t>
#define Flags64(EnumType) Flags<EnumType, uint64_t>
