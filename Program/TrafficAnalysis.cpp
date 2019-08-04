#include <unordered_map>

#include "TrafficAnalysis.h"
#include "FilterIP.h"
#include "FilterSCTPHeader.h"
#include "FilterTCPHeader.h"
#include  "FilterUDPHeader.h"

namespace Ethernet
{
#define   ETH_PUP 0x0200          /* Xerox PUP */
#define   ETH_SPRITE  0x0500    /* Sprite */
#define   ETH_IP  0x0800    /* IP */
#define   ETH_ARP  0x0806    /* Address resolution */
#define   ETH_REVARP  0x8035    /* Reverse ARP */
#define   ETH_AT  0x809B    /* AppleTalk protocol */
#define   ETH_AARP  0x80F3   /* AppleTalk ARP */
#define   ETH_VLAN  0x8100    /* IEEE 802.1Q VLAN tagging */
#define   ETH_MPLS  0x8847    /* MultiProtocol Label Switched protocol */
#define   ETH_IPX  0x8137    /* IPX */
#define   ETH_IPV6  0x86dd    /* IP protocol version 6 */
#define   ETH_LOOPBACK  0x9000    /* used to test interfaces */

#define   CONN_TCP 0x06
#define   CONN_UDP 0x11
#define   CONN_SCTP 0x84
#define   CONN_IP 0xff
}

inline bool isSomeEthernetProto(uint16_t proto)
{
  return proto == ETH_PUP || proto == ETH_SPRITE || proto == ETH_IP || proto == ETH_ARP || proto == ETH_REVARP || proto == ETH_AT
    || proto == ETH_AARP || proto == ETH_VLAN || proto == ETH_MPLS || proto == ETH_IPX || proto == ETH_IPV6 || proto == ETH_LOOPBACK;
}

inline bool isSomeConnectionProto(uint8_t proto)
{
  return proto == CONN_TCP || proto == CONN_UDP || proto == CONN_SCTP;
}

inline uint16_t getRightIndex(const char* originStr, const char* matchableStr, uint16_t matchableStrOffset)
{
  for (uint16_t i = 0; i < matchableStrOffset; ++i)
  {
    if (memcmp((originStr + i), matchableStr, (matchableStrOffset - i)) == 0)
    {
      return (matchableStrOffset - i);
    }
  }
  return 0;
}

inline bool fastFindAnyValue(const char* data, uint64_t dataSize, const PCAP::StringParams& values)
{
  uint64_t Size_find;
  uint64_t i, vi, viCur;
  std::vector<uint16_t> valuesIndex(values.size(), 0);

  for (i = 0; i < dataSize; ++i)
  {
    viCur = vi = 0;
    for (const auto& val : values)
    {
      viCur = vi++;
      Size_find = val.length();
      if (dataSize < Size_find || (valuesIndex[viCur] == 0 && Size_find > (dataSize - i))) continue;

      if (val.data()[valuesIndex[viCur]] == data[i])
      {
        ++valuesIndex[viCur];
        if (valuesIndex[viCur] == Size_find)
        {
          return true;
          //valuesIndex[viCur] = 0;
        }
      }
      else if (valuesIndex[viCur] != 0)
      {
        valuesIndex[viCur] = getRightIndex((data + (i - valuesIndex[viCur] + 1)), val.data(), valuesIndex[viCur]);
      }
    }
  }
  return false;
}

inline bool fastFindAnyValue(const char* data, uint64_t dataSize, const PCAP::StringParams& values, const PCAP::HashedStringParams& hashedVals)
{
  std::vector<uint64_t> tmpBeginOccurances;

  for (uint64_t i = 0; i < dataSize; ++i) {
    for (auto offsetOccIter = tmpBeginOccurances.begin(); offsetOccIter != tmpBeginOccurances.end();) {
      std::string occStr(data + (*offsetOccIter), i - (*offsetOccIter) + 1);
      auto res = hashedVals.find(occStr);

      // if occurance not match more then delete current occurance and continue
      if (res == hashedVals.end()) {
        offsetOccIter = tmpBeginOccurances.erase(offsetOccIter);
        continue;
      }

      // has found it
      if (res->second) return true;
      
      ++offsetOccIter;
    }

    // add a begin of new occurance if it matches with hash
    std::string occStr(data + i, 1);
    auto res = hashedVals.find(occStr);
    if (res != hashedVals.end()) {
      if (res->second) return true;
      tmpBeginOccurances.push_back(i);
    }
  }
  return false;
}

bool isNeededPacket(uint64_t SizeFrame, const char *Data, const Request& request, Answer& respone, TransportCounterMap* dropsTransportPtr, NetworkCounterMap* dropsNetworkPtr)
{
  using namespace FilterTraffic;

  const ip4_header  *IPv4 = nullptr;
  const ip6_header  *IPv6 = nullptr;
  const sctp_header *SCTP = nullptr;
  const tcp_header  *TCP = nullptr;
  const udp_header  *UDP = nullptr;

  uint64_t offsetData = 0;
  uint64_t lenData = 0;
  const char* transportData = nullptr;
  const char* BeginData = nullptr;

  uint16_t nextProtoType = Swap16(*reinterpret_cast<const uint16_t*>(&Data[START_TYPE_FRAME]));

  uint16_t ofsetIP = 0;

  uint8_t  ProtocolType = 0;

  uint64_t lenIP = 0;
  uint64_t lenIpPayload = 0;

  while(true) {
    if (nextProtoType == ETH_VLAN) {
      ofsetIP += 4;
      nextProtoType = Swap16(*reinterpret_cast<const uint16_t*>(&Data[START_TYPE_FRAME + ofsetIP]));
    }
    else if (nextProtoType == ETH_MPLS) {
      uint8_t bLastMPLSHeaderInSequence;
      do {
        ofsetIP += 4;
        bLastMPLSHeaderInSequence = (*reinterpret_cast<const uint8_t*>(&Data[START_TYPE_FRAME + ofsetIP])) & 0x1;
      } while (!bLastMPLSHeaderInSequence);
      // check may be this is ipv4
      uint8_t nextProtoForIPv4 = (*reinterpret_cast<const uint8_t*>(&Data[START_TYPE_FRAME + ofsetIP + 11]));
      uint16_t nextProtoForEth = Swap16(*reinterpret_cast<const uint16_t*>(&Data[START_TYPE_FRAME + ofsetIP + 14]));
      
      if(isSomeEthernetProto(nextProtoForEth)) {
        // other protos
        // default: ethernet offset to bytes of a type of next protocol
        ofsetIP += 14;
        nextProtoType = Swap16(*reinterpret_cast<const uint16_t*>(&Data[START_TYPE_FRAME + ofsetIP]));
      }
      else if (isSomeConnectionProto(nextProtoForIPv4)) {
        // ip
        //ofsetIP += 0;
        nextProtoType = ETH_IP;
        continue;
      }
      else {
        if (dropsNetworkPtr) {
          if (dropsNetworkPtr->count(nextProtoType) == 0) dropsNetworkPtr->emplace(nextProtoType, 0);
          auto it = dropsNetworkPtr->find(nextProtoType);
          if (it != dropsNetworkPtr->end() && !((++it->second) % 1000000)) {
            std::cout << "[DROP][Protocol 0x" << std::hex << (unsigned int)(nextProtoType) << "] count of drops: " << std::dec << it->second << std::endl << std::flush;
          }
        }
        return false;
      }
    }
    else if (nextProtoType == ETH_IP) {
      IPv4 = reinterpret_cast<const ip4_header *>(&Data[START_TYPE_FRAME + ofsetIP + 2]);

      lenIP = (IPv4->version_ihl & 0x0f) * 4;
      lenIpPayload = IPv4->total_length - 4 + lenIP;
      transportData = reinterpret_cast<const char*>(IPv4) + lenIP;

      bool isLastSegment = !(IPv4->fragment_offset & 0x20);
      uint16_t ipOffsetSegment = Swap16(IPv4->fragment_offset & 0xff1f);
      bool isSegment = !(IPv4->fragment_offset & 0x40);
      
      respone.flags = SessionResult::IsIPv4;
      respone.SRC.IPv4 = Swap32(IPv4->src_addr.ip_32);
      respone.DST.IPv4 = Swap32(IPv4->dst_addr.ip_32);
      respone.SRC.ipSegmentId = Swap16(IPv4->packet_id);
      respone.DST.ipSegmentId = Swap16(IPv4->packet_id);

      if (!isSegment || (ipOffsetSegment == 0 && (IPv4->next_proto_id == CONN_TCP || IPv4->next_proto_id == CONN_UDP || IPv4->next_proto_id == CONN_SCTP || isLastSegment))) {
        ProtocolType = IPv4->next_proto_id;
      }
      else {
        ProtocolType = CONN_IP;
      }
      offsetData = lenIP + ofsetIP + START_TYPE_FRAME + 2;
      break;
    }
    else if(nextProtoType == ETH_IPV6) {
      IPv6 = reinterpret_cast<const ip6_header *>(&Data[START_TYPE_FRAME + ofsetIP + 2]);
      ProtocolType = IPv6->proto;
      respone.flags = SessionResult::IsIPv6;
      lenIP = sizeof(IPv6);
      respone.SRC.IPv6 = reinterpret_cast<const uint8_t*>(IPv6->src_addr);
      respone.DST.IPv6 = reinterpret_cast<const uint8_t*>(IPv6->dst_addr);
      transportData = reinterpret_cast<const char*>(IPv6) + lenIP;
      offsetData = lenIP + ofsetIP + START_TYPE_FRAME + 2;
      break;
    }
    else { 
      if (dropsNetworkPtr) {
        if (dropsNetworkPtr->count(nextProtoType) == 0) dropsNetworkPtr->emplace(nextProtoType, 0);
        auto it = dropsNetworkPtr->find(nextProtoType);
        if (it != dropsNetworkPtr->end() && !((++it->second) % 1000000)) {
          std::cout << "[DROP][Protocol 0x" << std::hex << (unsigned int)(nextProtoType) << "] count of drops: " << std::dec << it->second << std::endl << std::flush;
        }
      }
      return false;
    }
  }

  uint64_t lenTransport = 0;
  
  switch (ProtocolType)
  {
    case CONN_TCP:
      TCP = reinterpret_cast<const tcp_header *>(transportData);
      respone.flags |=  SessionResult::IsTCP;
      respone.SRC.Port = Swap16(TCP->src_port);
      respone.DST.Port = Swap16(TCP->dst_port);
      lenTransport = ((TCP->lenheader & 0xf0) >> 4) * 4;
      offsetData += lenTransport;
      lenData = SizeFrame > offsetData ? SizeFrame - offsetData : 0;
      BeginData = lenData == 0 ? nullptr : reinterpret_cast<const char*>(TCP) + lenTransport;
      break;
    case CONN_UDP:
      UDP = reinterpret_cast<const udp_header *>(transportData);
      respone.flags |= SessionResult::IsUDP;
      respone.SRC.Port = Swap16(UDP->src_port);
      respone.DST.Port = Swap16(UDP->dst_port);
      lenTransport = sizeof(udp_header);
      offsetData += lenTransport;
      lenData = SizeFrame > offsetData ? SizeFrame - offsetData : 0; 
      /* if ip segmented then here is bug with this code: 
      lenData = Swap16(UDP->dgram_len) - lenTransport;
      lenData = lenData > (SizeFrame - offsetData) ? lenData : SizeFrame - offsetData;
      */
      BeginData = lenData == 0 ? nullptr : reinterpret_cast<const char*>(UDP) + lenTransport;
      break;
    case CONN_SCTP:
    {
      SCTP = reinterpret_cast<const sctp_header *>(transportData);
      respone.flags |= SessionResult::IsSCTP;
      respone.SRC.Port = Swap16(SCTP->src_port);
      respone.DST.Port = Swap16(SCTP->dst_port);
      lenTransport = sizeof(sctp_header);
      offsetData += lenTransport;
      lenData = SizeFrame > offsetData ? SizeFrame - offsetData : 0;
      BeginData = lenData == 0 ? nullptr : reinterpret_cast<const char*>(SCTP) + lenTransport;
      break;
    }
    case CONN_IP:
    {
      lenData = SizeFrame > offsetData ? SizeFrame - offsetData : 0;
      BeginData = transportData;
      break;
    }
    default:
    {
      if (dropsTransportPtr) {
        if (dropsTransportPtr->count(ProtocolType) == 0) dropsTransportPtr->emplace(ProtocolType, 0);
        auto it = dropsTransportPtr->find(ProtocolType);
        if (it != dropsTransportPtr->end() && !((++it->second) % 1000000)) {
          std::cout << "[DROP][Protocol 0x" << std::hex << (unsigned int)(ProtocolType) << "] count of drops: " << std::dec << it->second << std::endl << std::flush;
        }
      }
      return false;
    }
  }

  if (request.flags.TestFlag(SessionRequest::ContainsDesired_ContentData) && BeginData != nullptr && lenData <= (SizeFrame - offsetData) && fastFindAnyValue(BeginData, lenData, request.ContentData, request.ContentHashedData))
  {
    respone.flags |= SessionResult::ContainsDesired_ContentData;
  }
  return true;
}

void logDroppedPkts(const NetworkCounterMap& netPkts, const TransportCounterMap& tranPkts) {
  if (netPkts.size()) {
    std::cout << "\n\r[DROPed network protocols]: ";
    bool firstIter = true;
    for (const auto& proto : netPkts) {
      if (firstIter) firstIter = false;
      else std::cout << ", ";
      std::cout << "0x" << std::hex << (unsigned int)proto.first << " (" << std::dec << proto.second << ((proto.second > 1) ? " packs)" : " pack)");
    }
    std::cout << std::endl << std::flush;
  }
  // result log of dropped packets (osi transport level)
  if (tranPkts.size()) {
    std::cout << "\r[DROPed transport protocols]: ";
    bool firstIter = true;
    for (const auto& proto : tranPkts) {
      if (firstIter) firstIter = false;
      else std::cout << ", ";
      std::cout << "0x" << std::hex << (unsigned int)proto.first << " (" << std::dec << proto.second << ((proto.second > 1) ? " packs)" : " pack)");
    }
    std::cout << std::endl << std::flush;
  }
}

