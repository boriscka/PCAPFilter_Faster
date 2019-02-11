#ifndef FilterDefines_H
#define FilterDefines_H
//
//
//
//#define IS_BIG_ENDIAN (*(uint16_t *)"\0\x2" == 0x200)
//
//#ifndef _SCALL
//#if defined _WIN32 || defined _CYGWIN_
//#define _SCALL __stdcall
//#else
//#define _SCALL
//#endif
//#endif
//
#ifdef __linux__ 
#define PACK_STRUCT_START
#define PACK_STRUCT_END __attribute__((__packed__))
#endif

#if defined _WIN32 || defined _CYGWIN_ 
#define PACK_STRUCT_START __pragma( pack(push, 1) )
#define PACK_STRUCT_END   __pragma( pack(pop) )
#endif

#endif //FilterDefines_H
//
