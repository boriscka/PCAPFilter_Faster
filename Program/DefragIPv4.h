#ifndef DefragIPv4
#define DefragIPv4

#include "FilterIP.h"
#include <map>
#include <list>

struct DefragData
{
  const char* DataFrame;
  const char* DataIPv4;
  uint32_t LengthFrame;
  uint32_t LengthIPv4Data;
  inline DefragData()
    : DataFrame(nullptr)
    , DataIPv4(nullptr)
    , LengthFrame(0)
    , LengthIPv4Data(0)
  {
  } 
  inline DefragData(const char* DataFrame, const char* dataIPv4, uint32_t lengthFrame, uint32_t lengthIPv4Data)
    : DataFrame(DataFrame)
    , DataIPv4(dataIPv4)
    , LengthFrame(lengthFrame)
    , LengthIPv4Data(lengthIPv4Data)
  {
  }
};

struct DefragIP
{
  static DefragData AddIPv4(uint32_t NetworkID, const char *Frame, uint32_t LengthFrame, const FilterTraffic::ip4_header* IPv4);
  static void EraseIPv4(uint32_t NetworkID, const FilterTraffic::ip4_header* IPv4);

};




#endif // !DefragIPv4
