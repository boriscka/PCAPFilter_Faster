#ifndef PCAP_WRITER_H
#define PCAP_WRITER_H

#include "PCAP_Common.h"

namespace PCAP {

class PCAP_Writer{
public:
  PCAP_Writer(const char *FullPath, TimeType type = TimeType::NanoSecunds, bool open = true);
  ~PCAP_Writer();
  void Close();
  void Open(const char * FullPath, TimeType type = TimeType::NanoSecunds);
  int Write(uint32_t Size, const char* Data, uint32_t sec, uint32_t nsec);

private:
  std::ofstream out;
  TimeType TType;
  std::string fullPath;

  bool isFirstOpen;

  const uint32_t MAX_SIZE_TO_WAIT_FLUSH = 4096;
  uint8_t flushCnter;
  uint32_t curSizeToWaitFlush;
};

}
#endif //PCAP_WRITER_H
