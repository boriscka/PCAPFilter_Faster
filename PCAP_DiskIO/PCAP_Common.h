#ifndef PCAP_COMMON_H
#define PCAP_COMMON_H

#include "memory.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>
#include <unordered_map>

namespace PCAP {

  typedef std::vector<std::string> StringParams;
  typedef std::unordered_map<std::string, bool> HashedStringParams;
  typedef std::vector<std::uint32_t> Uint32Params;
  typedef std::vector<std::uint16_t> Uint16Params;
  
  const uint32_t MAX_PACKET_LEN = 100000;

#pragma pack(push, 1)

typedef struct pcap_hdr_s {
  uint32_t magic_number;   /* magic number */
  uint16_t version_major;  /* major version number */
  uint16_t version_minor;  /* minor version number */
  int32_t  thiszone;       /* GMT to local correction */
  uint32_t sigfigs;        /* accuracy of timestamps */
  uint32_t snaplen;        /* max length of captured packets, in octets */
  uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
  uint32_t ts_sec;         /* timestamp seconds */
  uint32_t ts_nsec;        /* timestamp nanoseconds */
  uint32_t incl_len;       /* number of octets of packet saved in file */
  uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

enum class TimeType : uint8_t {
  MicroSecunds,
  NanoSecunds
};

#pragma pack(pop)

static_assert(sizeof(struct pcap_hdr_s)    == 24, "sizeof(struct pcap_hdr_s)    == 24");
static_assert(sizeof(struct pcaprec_hdr_s) == 16, "sizeof(struct pcaprec_hdr_s) == 16");

class DataPacket{
private:
  pcaprec_hdr_s _header;
  char           *_data;
public:

  inline DataPacket(){
    _data = nullptr;
  }

  inline DataPacket(pcaprec_hdr_s header, const char* data){
    _data = new char[_header.orig_len];
    _header = header;
    memcpy(_data, data, header.orig_len);
  }

  inline DataPacket(const DataPacket &other){
    _header = other._header;
    if(other._data != nullptr && _header.orig_len > 0){
      _data = new char[_header.orig_len];
      memcpy(_data, other._data, _header.orig_len);
    }else{
      _data = nullptr;
    }
  }

  inline ~DataPacket(){
    if(_data != nullptr){
      delete[] _data;
    }
  }

  inline char *Release(){
    char *retval = _data;
    _data = nullptr;
    _header.ts_nsec  = 0,
    _header.ts_sec   = 0,
    _header.incl_len = 0,
    _header.orig_len = 0;
    return retval;
  }

  inline void Init(const pcaprec_hdr_s &header, char* data){
    if(_data != nullptr){
      delete[] _data;
    }
    _data   = data;
    _header = header;
  }

  inline const pcaprec_hdr_s &GetHeader() const{
    return _header;
  }

  inline const char *GetData() const{
    return _data;
  }

};

}

#endif//PCAP_COMMON_H
