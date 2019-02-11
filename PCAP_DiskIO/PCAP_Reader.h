#include <list>
#include "PCAP_Common.h"

namespace PCAP {
  class PCAP_Reader{
    pcap_hdr_t HeaderPcapFile;
    std::fstream in;
    volatile bool IsReading;
    TimeType TType;
  public:
    PCAP_Reader(const char *FullPath);
    ~PCAP_Reader();
    int Read(uint32_t &Size, char* Data, uint32_t &sec, uint32_t &nsec);
    int ReadALL(std::list<DataPacket> & ListPackeds);
    bool IsEOF();
  };
}
