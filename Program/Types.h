#ifndef TypesH
#define TypesH

#include <unordered_set>
#include <unordered_map>
#include <memory>

#include "Flags.h"
#include "UInts.h"
#include "..\PCAP_DiskIO\PCAP_Common.h"

struct Statistics
{
  uint64_t counterPacketRead;
  uint64_t counterPacketWrite;
  uint64_t counterPacketDropped;
  Statistics()
    :counterPacketRead(0)
    ,counterPacketWrite(0)
    ,counterPacketDropped(0)
  { }
};

enum class SessionResult : uint16_t
{
  NONE = 0,
  IsWLAN = 1 << 0,
  IsIPv4 = 1 << 1,
  IsIPv6 = 1 << 2,
  IsUDP = 1 << 3,
  IsTCP = 1 << 4,
  IsSCTP = 1 << 5,
  ContainsDesired_ipV4 = 1 << 6,
  ContainsDesired_ipV4_SRC = 1 << 7,
  ContainsDesired_ipV4_DST = 1 << 8,
  ContainsDesired_ipV6 = 1 << 9,
  ContainsDesired_ipV6_SRC = 1 << 10,
  ContainsDesired_ipV6_DST = 1 << 11,
  ContainsDesired_Port = 1 << 12,
  ContainsDesired_Port_SRC = 1 << 13,
  ContainsDesired_Port_DST = 1 << 14,
  ContainsDesired_ContentData = 1 << 15,
};

enum class SessionRequest : uint16_t
{
  NONE = 0,
  IsWLAN = 1 << 0,
  IsIPv4 = 1 << 1,
  IsIPv6 = 1 << 2,
  IsUDP = 1 << 3,
  IsTCP = 1 << 4,
  IsSCTP = 1 << 5,
  ContainsDesired_ipV4 = 1 << 6,
  ContainsDesired_ipV4Point = 1 << 7,
  ContainsDesired_ipV6 = 1 << 8,
  ContainsDesired_Port = 1 << 9,
  ContainsDesired_ContentData = 1 << 10,
  BothEP = 1 << 11,
  ToWriteDrops = 1 << 12
};

struct EndPoint
{
  EndPoint() : IPv4(0), IPv6(0), Port(0), ipSegmentId(0)
  {
  }

  bool operator<(const EndPoint& other) const
  {
    if (IPv4 != 0 || IPv6 == 0 || other.IPv4 != 0 || other.IPv6 == 0)
    {
      if (IPv4 != other.IPv4) return IPv4 < other.IPv4;
    }
    else
    {
      if (IPv6 != other.IPv6) return IPv6 < other.IPv6;
    }
    if (Port != other.Port) return Port < other.Port;
    if (ipSegmentId != other.ipSegmentId) return ipSegmentId < other.ipSegmentId;
    return false;
  }
  virtual bool operator==(const EndPoint& other) const
  {
    return ((IPv4 != 0 || IPv6 == 0) ? (IPv4 == other.IPv4) : (IPv6 == other.IPv6))
      && ((Port == other.Port) || (ipSegmentId == other.ipSegmentId));
  }

  operator bool() const
  {
    return (IPv4 != 0 || IPv6 != 0) && (Port != 0 || ipSegmentId != 0);
  }

  std::string toString() const
  {
    std::string addInfo;
    if (IPv6 != 0) addInfo += IPv6.toString();
    return std::to_string(IPv4) + "_" + addInfo + "_ep_" + std::to_string(Port);
  }
  std::string toStringIpSeg() const
  {
    std::string addInfo;
    if (IPv6 != 0) addInfo += IPv6.toString();
    return std::to_string(IPv4) + "_" + addInfo + "_ip_seg_" + std::to_string(ipSegmentId);
  }

public:
  uint32_t  IPv4;
  uint128_t IPv6;
  uint16_t  Port;
  uint16_t  ipSegmentId;
};

class EndPointExt : public EndPoint
{
public:
  uint16_t  ipSegmentIdSrc;
  uint16_t  ipSegmentIdDst;

  EndPointExt()
    : EndPoint(), ipSegmentIdSrc(0), ipSegmentIdDst(0)
  {
  }

  bool operator==(const EndPoint& other) const
  {
    return ((IPv4 == other.IPv4) || (IPv6 != 0 && IPv6 == other.IPv6))
      && ((Port != 0 && Port == other.Port) || (ipSegmentIdSrc != 0 && ipSegmentIdSrc == other.ipSegmentId) || (ipSegmentIdDst != 0 && ipSegmentIdDst == other.ipSegmentId));
  }
};

typedef std::vector<EndPointExt> EPParams;

// types for hash search of fragments
typedef std::unordered_set<uint32_t> SecMap;
typedef std::shared_ptr<SecMap> SecMapSPtr;
typedef std::unordered_map<std::string, SecMapSPtr> FoundPoints;

struct Answer
{
  EndPoint SRC;
  EndPoint DST;
  Flags16(SessionResult) flags;
  uint64_t pacnum = 0;
  uint32_t sec = 0;
  uint32_t nanosec = 0;
  
  bool operator<(const Answer& other) const
  {
    if (SRC < other.SRC) return true;
    else if (other.SRC < SRC) return false;
    
    if (DST < other.DST) return true;
    else if (other.DST < DST) return false;

    if (flags < other.flags) return true;
    else if (other.flags < flags) return false;

    if (pacnum < other.pacnum) return true;
    return false;
  }

  operator bool() const { return SRC && DST; }

  bool getKeyIp(std::string& str) const {
    str.clear();
    str = (flags.TestFlag(SessionResult::IsIPv4) ? "ip4" : (flags.TestFlag(SessionResult::IsIPv6) ? "ip6" : "unknown"));
    str += "-" + SRC.toStringIpSeg() + "-" + DST.toStringIpSeg();
    return (SRC.ipSegmentId != 0);
  }
  bool getReverseKeyIp(std::string& str) const {
    str.clear();
    str = (flags.TestFlag(SessionResult::IsIPv4) ? "ip4" : (flags.TestFlag(SessionResult::IsIPv6) ? "ip6" : "unknown"));
    str += "-" + DST.toStringIpSeg() + "-" + SRC.toStringIpSeg();
    return (DST.ipSegmentId != 0);
  }
  bool getKeyEP(std::string& str) const {
    str.clear();
    str = (flags.TestFlag(SessionResult::IsIPv4) ? "ip4" : (flags.TestFlag(SessionResult::IsIPv6) ? "ip6" : "unknown"));
    str += "-" + SRC.toString() + "-" + DST.toString();
    return (SRC.Port != 0);
  }
  bool getReverseKeyEP(std::string& str) const {
    str.clear();
    str = (flags.TestFlag(SessionResult::IsIPv4) ? "ip4" : (flags.TestFlag(SessionResult::IsIPv6) ? "ip6" : "unknown"));
    str += "-" + DST.toString() + "-" + SRC.toString();
    return (DST.Port != 0);
  }
  bool getKeyPacketNumber(std::string& str) const {
    str.clear();
    str = "pacnum_" + std::to_string(pacnum);
    return pacnum > 0;
  }

  inline std::vector<uint32_t> getDottedSecInterval() const {
    static uint32_t timeoutLimit = 2;
    std::vector<uint32_t> res;

    for (uint32_t i = 0; i < (timeoutLimit << 1); ++i) res.push_back(sec + i - timeoutLimit);
    
    return res;
  }
};

struct Request
{
  EndPoint Point;
  PCAP::StringParams ContentData;
  PCAP::Uint16Params portsUdp;
  PCAP::Uint32Params addrsIp4;
  EPParams eps;
  Flags16(SessionRequest) flags;

  uint64_t packetsCount = 0;
  uint64_t packetOffset = 0;
};


#endif // !TypesH