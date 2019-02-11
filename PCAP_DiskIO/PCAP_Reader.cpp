#include "PCAP_Reader.h"

namespace PCAP {

  PCAP_Reader::PCAP_Reader(const char *FullPath)
  {
    IsReading = false;
    in.open(FullPath, std::ios::binary | std::ios::in);
    if(in.is_open()){
      in.read((char*)&HeaderPcapFile, sizeof(HeaderPcapFile));
      TType = HeaderPcapFile.magic_number == 0xa1b2c3d4 ? TimeType::MicroSecunds : TimeType::NanoSecunds;
      std::cout << "File " << FullPath << " is opening" << std::endl;
    }else{
      std::cout << "File " << FullPath << " no opening" << std::endl;
    }
  }

  PCAP_Reader::~PCAP_Reader()
  {
    in.close();
  }

  bool PCAP_Reader::IsEOF()
  {
    return in.is_open() ? in.eof() : true;
  }

  int PCAP_Reader::Read(uint32_t &Size, char* Data, uint32_t &sec, uint32_t &nsec)
  {
    pcaprec_hdr_t  HeaderPacket;
    memset(&HeaderPacket, 0, sizeof(HeaderPacket));
    int retval = 0;
    if(in.is_open() && !IsReading){
      if(!in.eof()){
        in.read((char*)&HeaderPacket, sizeof(HeaderPacket));
        if(HeaderPacket.orig_len > 0 && HeaderPacket.orig_len < PCAP::MAX_PACKET_LEN && HeaderPacket.ts_sec > 0){
          Size = HeaderPacket.orig_len;
          sec = HeaderPacket.ts_sec;
          nsec = TType == TimeType::NanoSecunds ? HeaderPacket.ts_nsec : HeaderPacket.ts_nsec * 1000;
          in.read(Data, HeaderPacket.orig_len);
          retval = 1;
        } else {
          Size = 0;
        }
      }
    }else{
      Data[0] = '\0';
      Size  = 0;
      sec   = 0;
      nsec  = 0;
    }
    return retval;
  }

  int PCAP_Reader::ReadALL(std::list<DataPacket> &ListPackets)
  {
    ListPackets.clear();
    if(in.is_open() && !IsReading){
      pcaprec_hdr_t  HeaderPacket;
      std::cout << "Start reading " << std::endl;
      while (!in.eof()) {
        in.read((char*)&HeaderPacket, sizeof(HeaderPacket));
        if(in.eof()) break;
        if(HeaderPacket.orig_len > 0){
          if(TType == TimeType::MicroSecunds) HeaderPacket.ts_nsec *= 1000;
          char* data = new char[HeaderPacket.orig_len];
          in.read(data, HeaderPacket.orig_len);
          DataPacket p;
          p.Init(HeaderPacket, data);
          ListPackets.push_back(p);
        }
      }
      std::cout << "End reading. Count pacets: " << ListPackets.size() << std::endl;
    }
    return static_cast<int>(ListPackets.size());
  }

}
