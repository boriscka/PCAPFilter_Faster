#ifndef FILTERDIRECT_H
#define FILTERDIRECT_H

#include "Types.h"

bool FilterDirect(Request& request, Statistics& stat, std::string FileNameInput, std::string FileNameOutput);
struct Finder {
  static bool FindDirectTransportPackets;
};

inline bool checkPacketActuality(uint32_t packetSec, uint64_t packetNum, const Request& request, bool begin) {
  if (begin) {
    if (request.packetOffset > 0 && request.packetOffset >= packetNum) return false;
    if (request.minSec != 0 && packetSec < request.minSec) return false;
  }
  else {
    if (request.packetsCount != 0 && packetNum > (request.packetOffset + request.packetsCount)) return false;
    if (request.maxSec != 0 && packetSec > request.maxSec) return false;
  }
  return true;
}

inline void clearCoutLine() {
  std::cout << "\r                                                                                                                                  \r";
}

#endif // !FILTERDIRECT_H
