#ifndef FilterDefines_H
#define FilterDefines_H


#if defined _MSC_VER
  // we can use Microsoft extensions
  #define PACK_STRUCT_START  __pragma(pack(push, 1))
  #define PACK_STRUCT_END  __pragma(pack(pop))
#elif defined(__MINGW32__)
  #define PACK_STRUCT_START _Pragma("pack(1)")
  #define PACK_STRUCT_END   _Pragma("pack()")
#elif defined(__GNUC__)
  // for GCC we try to use GNUC_PACKED
  #define PACK_STRUCT_START
  #define PACK_STRUCT_END
#elif defined(HAVE_ISOC99_PRAGMA)
  // should work with most EDG-frontend based compilers
  #define PACK_STRUCT_START _Pragma("pack(1)")
  #define PACK_STRUCT_END   _Pragma("pack()")
#else  // neither gcc nor _Pragma() available...
    // ...so let's be naive and hope the regression testsuite is run...
  #define PACK_STRUCT_START
  #define PACK_STRUCT_END
#endif  // _MSC_VER

#endif //FilterDefines_H
