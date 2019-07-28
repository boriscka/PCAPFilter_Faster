#include <assert.h>

#include <set>
#include <unordered_set>
#include <unordered_map>
#include <memory>

#include "../PCAP_DiskIO/PCAP_Reader.h"
#include "../PCAP_DiskIO/PCAP_Writer.h"

#include "FilterDirect.h"
#include "TrafficAnalysis.h"

bool  Finder::FindDirectTransportPackets = false;

inline bool IsWrite(const Request& request, const Answer& respone)
{
  if (request.minSec != 0 && request.minSec > respone.sec || request.maxSec != 0 && request.maxSec < respone.sec) return false;
  if ((request.flags & SessionRequest::ContainsDesired_ContentData) || (request.flags & SessionRequest::ContainsDesired_ipV4Point)
      || (request.flags & SessionRequest::ContainsDesired_ipV4) || (request.flags & SessionRequest::ContainsDesired_Port))
  {
    if ((request.flags & SessionRequest::ContainsDesired_ContentData) && (respone.flags & SessionResult::ContainsDesired_ContentData))
    {
      return true;
    }
    if (request.flags & SessionRequest::ContainsDesired_ipV4Point)
    {
      bool isSrcFound = false;
      bool isDstFound = false;
      for (const auto& ep : request.eps)
      {
        if (!isSrcFound && ep == respone.SRC)
        {
          isSrcFound = true;
        }
        if (!isDstFound && ep == respone.DST)
        {
          isDstFound = true;
        }
        if ((isSrcFound || isDstFound) && ((isSrcFound && isDstFound) || !(request.flags & SessionRequest::BothEP))) return true;
      }
    }
    if (request.flags & SessionRequest::ContainsDesired_ipV4)
    {
      for (const auto& ip4 : request.addrsIp4)
      {
        if (ip4 == respone.SRC.IPv4 || ip4 == respone.DST.IPv4)
        {
          return true;
        }
      }
    }
    if (request.flags & SessionRequest::ContainsDesired_Port)
    {
      for (const auto& port : request.portsUdp)
      {
        if (port == respone.SRC.Port || port == respone.DST.Port)
        {
          return true;
        }
      }
    }
  }
  else
  {
    if ((request.flags & SessionRequest::IsIPv4) && (respone.flags & SessionResult::IsIPv4))
    {
      return true;
    }
    if ((request.flags & SessionRequest::IsIPv6) && (respone.flags & SessionResult::IsIPv6))
    {
      return true;
    }
    if ((request.flags & SessionRequest::IsTCP) && (respone.flags & SessionResult::IsTCP))
    {
      return true;
    }
    if ((request.flags & SessionRequest::IsUDP) && (respone.flags & SessionResult::IsUDP))
    {
      return true;
    }
    if ((request.flags & SessionRequest::IsSCTP) && (respone.flags & SessionResult::IsSCTP))
    {
      return true;
    }
  }
  return false;
}

// slow function: restricted
bool IsWrite(const Answer& Session, const Answer& respone)
{
  if ((Session.SRC == respone.SRC && Session.DST == respone.DST
       /* if here is needed direct transport packet only then will get only packets with same ip segment id */
       && (!Finder::FindDirectTransportPackets || Session.SRC.ipSegmentId == respone.SRC.ipSegmentId))
      /* if here is needed direct transport packets and packets from same transport session */
      || (!Finder::FindDirectTransportPackets && Session.DST == respone.SRC && Session.SRC == respone.DST))
  {
    if (Session.flags.TestFlag(SessionResult::IsIPv4) && respone.flags.TestFlag(SessionResult::IsIPv4))
    {
      return true;
    }
    if (Session.flags.TestFlag(SessionResult::IsIPv6) && respone.flags.TestFlag(SessionResult::IsIPv6))
    {
      return true;
    }
    if (Session.flags.TestFlag(SessionResult::IsUDP) && respone.flags.TestFlag(SessionResult::IsUDP))
    {
      return true;
    }
    if (Session.flags.TestFlag(SessionResult::IsTCP) && respone.flags.TestFlag(SessionResult::IsTCP))
    {
      return true;
    }
    if (Session.flags.TestFlag(SessionResult::IsSCTP) && respone.flags.TestFlag(SessionResult::IsSCTP))
    {
      return true;
    }
  }
  return false;
}

inline bool checkSegmentActuality(uint32_t secKey, const SecMapSPtr& secMap)
{
  return secMap ? (secMap->count(secKey) > 0) : false;
}


bool FilterDirect(Request& request, Statistics& stat, std::string FileNameInput, std::string FileNameOutput) {
  char Buffer[256 * 1024];
  FoundPoints FoundPoints;

  bool isOnlyOutsideConditions = (request.minSec != 0 || request.maxSec != 0 || request.packetsCount != 0 || request.packetOffset != 0)
    && !(request.flags.TestFlag(SessionRequest::ContainsDesired_ContentData) || request.flags.TestFlag(SessionRequest::ContainsDesired_ipV4Point)
      || request.flags.TestFlag(SessionRequest::ContainsDesired_ipV4) || request.flags.TestFlag(SessionRequest::ContainsDesired_Port)
      || request.flags.TestFlag(SessionRequest::IsIPv4) || request.flags.TestFlag(SessionRequest::IsIPv6) || request.flags.TestFlag(SessionRequest::IsSCTP)
      || request.flags.TestFlag(SessionRequest::IsTCP) || request.flags.TestFlag(SessionRequest::IsUDP) || request.flags.TestFlag(SessionRequest::IsWLAN));

  // block of FIRST SEARCH: by requests, will find some segments and small packets, which is needed
  if(!isOnlyOutsideConditions)
  {
    std::cout << "\n\r[SEARCH]" << std::endl << std::flush;
    PCAP::PCAP_Reader Reader(FileNameInput.c_str());
    PCAP::PCAP_Writer WriterDroppedPackets("dropped_at_search.pcap", PCAP::TimeType::NanoSecunds, false);
        
    std::set<Answer> FoundPointSets;
    while (!Reader.IsEOF())
    {
      Answer response;
      uint32_t ReadOk, Sec, NSec;

      Reader.Read(ReadOk, Buffer, Sec, NSec);
      assert(ReadOk < sizeof(Buffer));
      ++stat.counterPacketRead;
      
      if (!checkPacketActuality(Sec, stat.counterPacketRead, request, false)) break;
      if (ReadOk == 0 || !checkPacketActuality(Sec, stat.counterPacketRead, request, true)) continue;
          
      if (TrafficAnalysis(ReadOk, Buffer, request, response)) {
        response.pacnum = stat.counterPacketRead;
        response.sec = Sec;
        response.nanosec = NSec;
        // filter
        if (IsWrite(request, response)) {
          FoundPointSets.insert(response);
        }
      }
      else {
        // drop
        if (request.flags.TestFlag(SessionRequest::ToWriteDrops)) {
          WriterDroppedPackets.Write(ReadOk, Buffer, Sec, NSec);
          if (!(++stat.counterPacketDropped % 1000000)) {
            std::cout << "\r[DROPs!!!] pacnum:  " << stat.counterPacketDropped << std::endl << std::flush;
          }
        }
      }
        
      // log
      if ((stat.counterPacketRead & 0x00000000000fffff) == 1) {
        clearCoutLine();
        std::cout << "[progress] ckecked packets: " << stat.counterPacketRead << "; found packets: " << FoundPointSets.size() << std::flush;
      }
    }
    clearCoutLine();

    FoundPoints.rehash(FoundPointSets.size() * 10); // need size more in 5*2 times to define max hash buckets (for optimal hash space)
    std::string bufstr;
    for (const auto& point : FoundPointSets) {
      std::vector<std::string> keys;
      if (!request.flags.TestFlag(SessionRequest::IpFragmentationOff) && point.getKeyIp(bufstr))           keys.push_back(bufstr);
      //if (point.getReverseKeyIp(bufstr))    keys.push_back(bufstr);
      if (point.getKeyEP(bufstr))           keys.push_back(bufstr);
      if (point.getReverseKeyEP(bufstr))    keys.push_back(bufstr);
      if (point.getKeyPacketNumber(bufstr)) keys.push_back(bufstr);

      SecMapSPtr sptr(new SecMap);
      const auto & secsIts = point.getDottedSecInterval();
      for (const std::string& strKey: keys) {
        auto it = FoundPoints.insert({ strKey,  sptr }).first;
        for (auto secVal : secsIts) {
          // store all time intervals for any found EP (which can repeats) and IP segments. This is needed for directly selection of packets (at transport layer)
          it->second->insert(secVal);
        }
      }
    }
  }
  
  // turn off a search by text (key -find or -fi), now select target packets by found packets at first circle of search
  request.flags.SetFlag(SessionRequest::ContainsDesired_ContentData, false);

  // block of SECOND SEARCH: will find remaining parts of ip segments for found transport sessions
  if (!request.flags.TestFlag(SessionRequest::IpFragmentationOff) && FoundPoints.size() > 0 && !isOnlyOutsideConditions) {
    stat.counterPacketRead = 0;
    stat.counterPacketAddedIpFrags = 0;
    std::cout << "\n\r[SEARCH REMAINING FRAGMENTS]" << std::endl << std::flush;
    std::cout << "found main packets: " << FoundPoints.size() << std::endl << std::flush;
    PCAP::PCAP_Reader Reader(FileNameInput.c_str());
    
    while (!Reader.IsEOF()) {
      Answer response;
      uint32_t ReadOk, Sec, NSec;

      Reader.Read(ReadOk, Buffer, Sec, NSec);
      assert(ReadOk < sizeof(Buffer));
      ++stat.counterPacketRead;

      if (!checkPacketActuality(Sec, stat.counterPacketRead, request, false)) break;
      if (ReadOk == 0 || !checkPacketActuality(Sec, stat.counterPacketRead, request, true)) continue;

      if (TrafficAnalysis(ReadOk, Buffer, request, response)) {
        response.pacnum = stat.counterPacketRead;
        response.sec = Sec;
        response.nanosec = NSec;
        std::string bufstr;
        if (response.getKeyEP(bufstr) && FoundPoints.count(bufstr) > 0) {
          if (!Finder::FindDirectTransportPackets || checkSegmentActuality(response.sec, FoundPoints.find(bufstr)->second)) {
            // if ipkey will be generated then check for existing of ip segment key at hash map
            if (response.getKeyIp(bufstr)) {
              // response.getReverseKeyIp(bufstr) -- do not we need process it too?
              bool isNewIt = false;
              auto foundIpTimeInterval = FoundPoints.find(bufstr);

              if (foundIpTimeInterval == FoundPoints.end()) {
                foundIpTimeInterval = FoundPoints.insert({ bufstr,  SecMapSPtr(new SecMap) }).first;
                isNewIt = true;
              }
              if (isNewIt || !checkSegmentActuality(response.sec, foundIpTimeInterval->second)) {
                auto secsIts = response.getDottedSecInterval();
                for(const auto& secondStamp: secsIts) foundIpTimeInterval->second->insert(secondStamp);
                ++stat.counterPacketAddedIpFrags;
              }
            }
          }
        }
        // log
        if ((stat.counterPacketRead & 0x00000000000fffff) == 1) {
          clearCoutLine();
          std::cout << "[progress] ckecked packets: " << stat.counterPacketRead << "; found packet segments: " << stat.counterPacketAddedIpFrags << std::flush;
        }
      }
    }
  }
  clearCoutLine();

  // block of THIRD SEARCH: will find remaining parts of segments and/or network sessions
  if (FoundPoints.size() > 0 || isOnlyOutsideConditions) {
    stat.counterPacketRead = 0;
    stat.counterPacketDropped = 0;
    std::cout << "\n\r[WRITING] " << std::endl << std::flush;
    std::cout << "found sessions: " << FoundPoints.size() << std::endl << std::flush;
    PCAP::PCAP_Reader Reader(FileNameInput.c_str());
    PCAP::PCAP_Writer Writer(FileNameOutput.c_str());

    TransportCounterMap dropsTransport;
    NetworkCounterMap dropsNetwork;

    while (!Reader.IsEOF()){
      Answer response;
      uint32_t ReadOk, Sec, NSec;

      Reader.Read(ReadOk, Buffer, Sec, NSec);
      assert(ReadOk < sizeof(Buffer));
      ++stat.counterPacketRead;

      if (!checkPacketActuality(Sec, stat.counterPacketRead, request, false)) break;
      if (ReadOk == 0 || !checkPacketActuality(Sec, stat.counterPacketRead, request, true)) continue;

      if (isOnlyOutsideConditions) {
        ++stat.counterPacketWrite;
        Writer.Write(ReadOk, Buffer, Sec, NSec);
        // log statistics
        if (!(stat.counterPacketRead % 1000000)) {
          if (!(stat.counterPacketRead % 30000000)) std::cout << "\r[READ] pacnum:  " << stat.counterPacketRead << "; [WRITE] pacnum: " << stat.counterPacketWrite << ";" << std::endl << std::flush;
          else std::cout << "-" << std::flush;
        }
      }
      else if (TrafficAnalysis(ReadOk, Buffer, request, response, &dropsTransport, &dropsNetwork)) {
        response.pacnum = stat.counterPacketRead;
        response.sec = Sec;
        response.nanosec = NSec;
        std::string bufstr;

        // prepare condition of end points
        bool hasSoEp = (response.getKeyEP(bufstr) && FoundPoints.count(bufstr) > 0);
        const auto& foundEPTimeIntervals(hasSoEp ? FoundPoints.find(bufstr)->second : SecMapSPtr(nullptr));
        // prepare condition of ip segments
        bool hasSoIpSeg = (!request.flags.TestFlag(SessionRequest::IpFragmentationOff)) ? (response.getKeyIp(bufstr) && FoundPoints.count(bufstr) > 0) : false;
        const auto& foundIPTimeIntervals(hasSoIpSeg ? FoundPoints.find(bufstr)->second : SecMapSPtr(nullptr));
        // prepare condition of packet number
        bool hasSoPacket = (response.getKeyPacketNumber(bufstr) && FoundPoints.count(bufstr) > 0);

        // WRITING of data in new pcap by the condition
        if (hasSoPacket || (hasSoEp && (!Finder::FindDirectTransportPackets || checkSegmentActuality(response.sec, foundEPTimeIntervals)))
          || (hasSoIpSeg && checkSegmentActuality(response.sec, foundIPTimeIntervals)))
        {
          ++stat.counterPacketWrite;
          Writer.Write(ReadOk, Buffer, Sec, NSec);
        }
        // log statistics
        if ((stat.counterPacketRead & 0x00000000000fffff) == 1) {
            clearCoutLine();
            std::cout << "[progress] ckecked packets: " << stat.counterPacketRead << "; found packet segments: " << stat.counterPacketWrite << std::flush;
        }
      }
    }
    clearCoutLine();

    // result log of dropped packets (osi network level)
    if (dropsNetwork.size()) {
      std::cout << "\n\r[DROPed network protocols]: ";
      bool firstIter = true;
      for (const auto& proto : dropsNetwork) {
        if (firstIter) firstIter = false;
        else std::cout << ", ";
        std::cout << "0x" << std::hex << (unsigned int)proto.first << " (" << std::dec << proto.second << ((proto.second > 1) ? " packs)" : " pack)");
      }
      std::cout << std::endl << std::flush;
    }
    // result log of dropped packets (osi transport level)
    if (dropsTransport.size()) {
      std::cout << "\r[DROPed transport protocols]: ";
      bool firstIter = true;
      for (const auto& proto : dropsTransport) {
        if (firstIter) firstIter = false;
        else std::cout << ", ";
        std::cout << "0x" << std::hex << (unsigned int)proto.first << " (" << std::dec << proto.second << ((proto.second > 1) ? " packs)" : " pack)");
      }
      std::cout << std::endl << std::flush;
    }

    return true;
  } 
  else {
    std::cout << "\n[SEARCH] sessions are not found... Stop. " << std::endl << std::flush;
    return false;
  }
}