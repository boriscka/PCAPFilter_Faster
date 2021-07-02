#include <assert.h>

#include <set>
#include <unordered_set>
#include <unordered_map>
#include <memory>

#include "FilterDirect.h"


bool  Finder::FindDirectTransportPackets = false;

bool isFound(const Request& request, const Answer& respone)
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
bool isFound(const Answer& Session, const Answer& respone)
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

inline bool checkSegmentActuality(uint32_t secKey, const SecMapSPtr& secMap) {
  return secMap && secMap->count(secKey);
}

inline bool needToBeWritten(const FoundPoints& foundPoints, const Request& request, const Answer& response, std::string& bufKey) {

  return response.getKeyPacketNumber(bufKey) && foundPoints.count(bufKey)

      || response.getKeyEP(bufKey) && foundPoints.count(bufKey)
         && (!Finder::FindDirectTransportPackets || checkSegmentActuality(response.sec, foundPoints.find(bufKey)->second))

      || !request.flags.TestFlag(SessionRequest::IpFragmentationOff) && response.getKeyIp(bufKey) && foundPoints.count(bufKey)
         && checkSegmentActuality(response.sec, foundPoints.find(bufKey)->second);
}


template<class T>
void goThroughFile(const char* input, FoundPoints& foundPoints, T& functor, Request& request, Statistics& stat) {
  char Buffer[256 * 1024];
  PCAP::PCAP_Reader Reader(input);
  stat.counterPacketRead = 0;
  stat.counterPacketAddedIpFrags = 0;
  stat.counterPacketDropped = 0;

  while (!Reader.IsEOF())
  {
    uint32_t ReadOk, Sec, NSec;

    Reader.Read(ReadOk, Buffer, Sec, NSec);
    assert(ReadOk < sizeof(Buffer));
    ++stat.counterPacketRead;

    if (!checkPacketActuality(Sec, stat.counterPacketRead, request, false)) break;
    if (ReadOk == 0 || !checkPacketActuality(Sec, stat.counterPacketRead, request, true)) continue;

    functor(foundPoints, ReadOk, Buffer, Sec, NSec);

    // log
    if ((stat.counterPacketRead & 0x00000000000fffff) == 1) {
      clearCoutLine();
      std::cout << "[progress] ckecked packets: " << stat.counterPacketRead << std::flush;
    }
  }
  clearCoutLine();

  functor(foundPoints);
}


bool FilterDirect(Request& request, Statistics& stat, std::string FileNameInput, std::string FileNameOutput) {
  FoundPoints foundPoints;
  
  bool isOnlyOutsideConditions = (request.minSec != 0 || request.maxSec != 0 || request.packetsCount != 0 || request.packetOffset != 0)
    && !(request.flags.TestFlag(SessionRequest::ContainsDesired_ContentData) || request.flags.TestFlag(SessionRequest::ContainsDesired_ipV4Point)
      || request.flags.TestFlag(SessionRequest::ContainsDesired_ipV4) || request.flags.TestFlag(SessionRequest::ContainsDesired_Port)
      || request.flags.TestFlag(SessionRequest::IsIPv4) || request.flags.TestFlag(SessionRequest::IsIPv6) || request.flags.TestFlag(SessionRequest::IsSCTP)
      || request.flags.TestFlag(SessionRequest::IsTCP) || request.flags.TestFlag(SessionRequest::IsUDP));

  // block of FIRST SEARCH: by requests, will find some segments and small packets, which is needed
  if(!isOnlyOutsideConditions) {
    std::cout << "\n\r[SEARCH]" << std::endl << std::flush;
    
    FirstStepFinder functor(request, stat);
    goThroughFile<FirstStepFinder>(FileNameInput.c_str(), foundPoints, functor, request, stat);
  }
  
  // turn off a search by text (key -find or -fi), now select target packets by found packets at first circle of search
  request.flags.SetFlag(SessionRequest::ContainsDesired_ContentData, false);

  // block of SECOND SEARCH: will find remaining parts of ip segments for found transport sessions
  if (!request.flags.TestFlag(SessionRequest::IpFragmentationOff) && !foundPoints.empty() && !isOnlyOutsideConditions) {
    std::cout << "\n\r[SEARCH REMAINING FRAGMENTS]" << std::endl << std::flush;
    std::cout << "found main packets: " << foundPoints.size() << std::endl << std::flush;

    SegmentsFinder functor(request, stat);
    goThroughFile<SegmentsFinder>(FileNameInput.c_str(), foundPoints, functor, request, stat);
  }

  // block of THIRD SEARCH: will find remaining parts of segments and/or network sessions
  if (!foundPoints.empty() || isOnlyOutsideConditions) {
    std::cout << "\n\r[WRITING] " << std::endl << std::flush;
    std::cout << "found sessions: " << foundPoints.size() << std::endl << std::flush;

    FinalFinder functor(FileNameOutput.c_str(), isOnlyOutsideConditions, request, stat);
    goThroughFile<FinalFinder>(FileNameInput.c_str(), foundPoints, functor, request, stat);

    return true;
  } 
  else {
    std::cout << "\n[SEARCH] sessions are not found... Stop. " << std::endl << std::flush;
    return false;
  }
}