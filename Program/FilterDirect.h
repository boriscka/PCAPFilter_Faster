#ifndef FILTERDIRECT_H
#define FILTERDIRECT_H

#include "Types.h"
#include "TrafficAnalysis.h"
#include "../PCAP_DiskIO/PCAP_Reader.h"
#include "../PCAP_DiskIO/PCAP_Writer.h"

bool needToBeWritten(const FoundPoints& foundPoints, const Request& request, const Answer& response, std::string& bufKey);
bool checkSegmentActuality(uint32_t secKey, const SecMapSPtr& secMap);
bool isFound(const Request& request, const Answer& respone);
bool isFound(const Answer& Session, const Answer& respone);

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

inline void setPacketProperties(Answer& response, uint64_t pktNum, uint32_t sec, uint32_t nanosec) {
  response.pacnum = pktNum;
  response.sec = sec;
  response.nanosec = nanosec;
}

class FirstStepFinder {
public:
  FirstStepFinder() = delete;

  FirstStepFinder(const Request& request, Statistics& stat) 
    : WriterDroppedPackets("dropped_at_search.pcap", PCAP::TimeType::NanoSecunds, false),
    request(request), stat(stat) {}

  inline void operator ()(FoundPoints& foundPoints, uint32_t ReadOk, const char* data, uint32_t Sec, uint32_t NSec) {
    Answer response;
    if (isNeededPacket(ReadOk, data, request, response)) {
      setPacketProperties(response, stat.counterPacketRead, Sec, NSec);
      // filter
      if (isFound(request, response)) {
        foundPointSets.insert(response);
      }
    }
    else {
      // drop
      if (request.flags.TestFlag(SessionRequest::ToWriteDrops)) {
        WriterDroppedPackets.Write(ReadOk, data, Sec, NSec);
      }
    }
  }

  inline void operator ()(FoundPoints& foundPoints) {
    foundPoints.rehash(foundPointSets.size() * 10); // need size more in 5*2 times to define max hash buckets (for optimal hash space)

    for (const auto& point : foundPointSets) {
      std::vector<std::string> keys;
      point.getKeys(keys, !request.flags.TestFlag(SessionRequest::IpFragmentationOff));

      for (const std::string& strKey : keys) {
        const auto& it = foundPoints.try_emplace(strKey).first;
        if (!it->second) it->second = std::make_shared<SecMap>();
        point.getDottedSecInterval(it->second);
      }
    }
  };

private:
  std::set<Answer> foundPointSets;
  PCAP::PCAP_Writer WriterDroppedPackets;

  const Request& request;
  Statistics& stat;
};

class SegmentsFinder {
public:
  SegmentsFinder() = delete;

  SegmentsFinder(const Request& request, Statistics& stat): request(request), stat(stat) { bufKey.reserve(250); }

  inline void operator ()(FoundPoints& foundPoints, uint32_t ReadOk, const char* data, uint32_t Sec, uint32_t NSec) {
    Answer response;
    if (isNeededPacket(ReadOk, data, request, response)) {
      setPacketProperties(response, stat.counterPacketRead, Sec, NSec);

      if (response.getKeyEP(bufKey) && foundPoints.count(bufKey)) {
        if (!Finder::FindDirectTransportPackets || checkSegmentActuality(response.sec, foundPoints.find(bufKey)->second)) {
          // if ipkey will be generated then check for existing of ip segment key at hash map
          if (response.getKeyIp(bufKey)) {
            auto foundIpTimes = foundPoints.try_emplace(bufKey);
            if (foundIpTimes.second) foundIpTimes.first->second = std::make_shared<SecMap>();

            if (foundIpTimes.second || !checkSegmentActuality(response.sec, foundIpTimes.first->second)) {
              response.getDottedSecInterval(foundIpTimes.first->second);
              ++stat.counterPacketAddedIpFrags;
            }
          }
        }
      }

    }
  }

  inline void operator ()(FoundPoints& foundPoints) {};

private:
  const Request& request;
  Statistics& stat;
  std::string bufKey;
};

class FinalFinder {
public:
  FinalFinder() = delete;

  FinalFinder(const char* output, bool outsideCond, const Request& request, Statistics& stat)
    : Writer(output), request(request), stat(stat), isOnlyOutsideConditions(outsideCond)
  { 
    bufKey.reserve(250); 
  }

  inline void operator ()(FoundPoints& foundPoints, uint32_t ReadOk, const char* data, uint32_t Sec, uint32_t NSec) {
    Answer response;
    setPacketProperties(response, stat.counterPacketRead, Sec, NSec);

    if (isOnlyOutsideConditions || isNeededPacket(ReadOk, data, request, response, &dropsTransport, &dropsNetwork)
      && needToBeWritten(foundPoints, request, response, bufKey))
    {
      ++stat.counterPacketWrite;
      Writer.Write(ReadOk, data, Sec, NSec);
    }
  }

  inline void operator ()(FoundPoints& foundPoints) {
    // result log of dropped packets (osi network level)
    logDroppedPkts(dropsNetwork, dropsTransport);
  };

private:
  PCAP::PCAP_Writer Writer;
  TransportCounterMap dropsTransport;
  NetworkCounterMap dropsNetwork;
  bool isOnlyOutsideConditions;

  const Request& request;
  Statistics& stat;
  std::string bufKey;
};

#endif // !FILTERDIRECT_H
