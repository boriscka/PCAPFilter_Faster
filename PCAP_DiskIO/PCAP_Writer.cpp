#include "PCAP_Writer.h"

namespace PCAP {

PCAP_Writer::PCAP_Writer(const char *FullPath, TimeType type, bool open)
  : fullPath(FullPath), TType(type), isFirstOpen(true), flushCnter(0), curSizeToWaitFlush(0)
{
  if(open)
    Open(FullPath, type);
}

PCAP_Writer::~PCAP_Writer(){
  if (out.is_open())
    out.close();
}

void PCAP_Writer::Close()
{
  if (out.is_open())
    out.close();
}

void PCAP_Writer::Open(const char *FullPath, TimeType type)
{
  if (out.is_open()) return;
  //TType = type;
  if (isFirstOpen) {
    out.open(FullPath, std::ofstream::binary | std::ofstream::trunc);
    std::cout << "Begining of record in the file \"" << FullPath << "\"" << std::endl;
  }
  else {
    out.open(FullPath, std::ofstream::binary | std::ofstream::ate | std::ofstream::app);
  }
  pcap_hdr_t Header;
  if (isFirstOpen) {
    switch (type)
    {
    case TimeType::MicroSecunds:
      Header.magic_number = 0xa1b2c3d4;
      break;
    case TimeType::NanoSecunds:
    default:
      Header.magic_number = 0xa1b23c4d;
      break;
    }
    Header.version_major = 0x0002;
    Header.version_minor = 0x0004;
    Header.thiszone = 0x00000000;
    Header.sigfigs = 0x00000000;
    Header.snaplen = 0x00000400; // 0x00040000
    Header.network = 0x00000001;
    if (out.is_open())
    {
      isFirstOpen = false;
      out.write(reinterpret_cast<const char*>(&Header), sizeof(Header));
      curSizeToWaitFlush += sizeof(Header);
    }
  }
}

int PCAP_Writer::Write(uint32_t Size, char* Data, uint32_t sec, uint32_t nsec){
  pcaprec_hdr_t Header;

  if (!out.is_open())
    Open(fullPath.c_str(), TType);
  
  if (curSizeToWaitFlush > (MAX_SIZE_TO_WAIT_FLUSH - sizeof(Header) - Size)) {
    curSizeToWaitFlush = 0;
    out.flush();
    // close it to see current size of the file in realtime in a file browser (one update in each N x MAX_SIZE_TO_WAIT_FLUSH bytes)
    if (!((++flushCnter) % 38160 /* N - empirical  computed number (not important rvalue) */)) {
      flushCnter = 0;
      Close();
      Open(fullPath.c_str(), TType);
    }
  }
  if(out.is_open()){
    if (nsec >= 1000000000) nsec -= 1000000000, sec++;
    Header.ts_sec = sec;
    Header.ts_nsec = TType == TimeType::MicroSecunds ? nsec / 1000 : nsec;
    Header.incl_len = Size;
    Header.orig_len = Size;
    
    out.write(reinterpret_cast<const char*>(&Header), sizeof(Header));
    out.write(Data, Size);
    curSizeToWaitFlush += sizeof(Header) + Size;
  }
  return 0;
}

}
