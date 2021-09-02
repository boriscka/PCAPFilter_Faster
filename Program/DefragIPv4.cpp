#include <cstring>

#include "UInts.h"
#include "DefragIPv4.h"
#include "FilterTCPHeader.h"
#include "FilterUDPHeader.h"
#include "FilterSCTPHeader.h"

struct HashForDefragRowsIVv4
{
  uint32_t src_addr;		/**< source address */
  uint32_t dst_addr;		/**< destination address */
  uint32_t network_id;
  uint16_t packet_id;

  HashForDefragRowsIVv4(uint16_t NetworkID, const FilterTraffic::ip4_header* IPv4)
    : network_id(NetworkID)
    , packet_id(IPv4->packet_id)
    , src_addr(IPv4->src_addr.ip_32)
    , dst_addr(IPv4->dst_addr.ip_32)
  {
  }

  bool operator<(const HashForDefragRowsIVv4& other) const
  {
    uint64_t S1 = packet_id + (static_cast<uint64_t>(network_id) << 32);
    uint64_t S2 = other.packet_id + (static_cast<uint64_t>(other.network_id) << 32);
    uint64_t S3 = src_addr + (static_cast<uint64_t>(dst_addr) << 32);
    uint64_t S4 = other.src_addr + (static_cast<uint64_t>(other.dst_addr) << 32);
    if (S1 == S2)
      return S1 < S2;
    else
      return S3 < S4;
  }
};

struct DefragRowIPv4
{
  struct BeginEndFragment
  {
    uint16_t Begin;
    uint16_t Size;
    BeginEndFragment()
      : Begin(0)
      , Size(0)
    {
    }
  };

  uint16_t MaxFragment;
  uint16_t CounterFragment;
  uint16_t StartIPv4;

  char summData[64 * 1024 - 64];

  BeginEndFragment Fragments[256];

  DefragRowIPv4()
  {
    MaxFragment = 0;
    CounterFragment = 0;
    StartIPv4 = 0;
  }

  bool IsContainsFragment(uint16_t Begin) const
  {
    for (uint16_t i = 0; i < CounterFragment; i++)
    {
      const BeginEndFragment& fragments = Fragments[i];
      if (fragments.Begin == Begin)
      {
        return fragments.Size > 0;
      }
    }
    return false;
  }

  void AddFragment(uint16_t Begin, uint16_t Size, const char* Data)
  {
    if (IsContainsFragment(Begin)) return;
    BeginEndFragment& fragments = Fragments[CounterFragment++];
    fragments.Begin = Begin;
    fragments.Size = Size;
    memcpy(&summData[StartIPv4 + (fragments.Begin << 3)], Data, Size << 3);
  }

  bool IsBuild() const
  {
    if (CounterFragment < 2) return false;
    uint16_t FindNextBegin = 0;
    for (uint16_t i = 0; i < CounterFragment; i++)
    {
      bool IsFind = false;
      for (uint16_t j = 0; j < CounterFragment; j++)
      {
        const BeginEndFragment& fragments = Fragments[j];
        if (fragments.Begin == FindNextBegin)
        {
          IsFind = true;
          FindNextBegin = fragments.Begin + fragments.Size;
          break;
        }
      }
      if (!IsFind) return false;
    }
    return true;
  }

  DefragData Build(const char *Frame, uint32_t LengthFrame, const FilterTraffic::ip4_header* IPv4)
  {
    const uint16_t lenIP((IPv4->version_ihl & 0x0f) << 2);
    const uint16_t LengthIPData(Swap16(IPv4->total_length) - lenIP);

    StartIPv4 = static_cast<uint16_t>(reinterpret_cast<const char*>(IPv4) - Frame) + lenIP;

    if(CounterFragment == 0) memcpy(&summData[0], Frame, StartIPv4);

    const uint16_t fragment_offset = Swap16(IPv4->fragment_offset);

    if (IPv4->packet_id != 0)
    {
      uint16_t fragment_offset_begin = fragment_offset & 0x1FFF;
      if (!(fragment_offset & 0x2000))
      {
        MaxFragment = fragment_offset_begin + (LengthIPData >> 3);
      }
      AddFragment(fragment_offset_begin, LengthIPData >> 3, reinterpret_cast<const char*>(IPv4) + lenIP);
      if (IsBuild())
      {
        FilterTraffic::ip4_header* IPv4Build = reinterpret_cast<FilterTraffic::ip4_header*>(&summData[StartIPv4 - lenIP]);
        IPv4Build->total_length = Swap16(MaxFragment << 3);
        IPv4Build->fragment_offset = 0;
        IPv4Build->packet_id = 0;
        return DefragData( &summData[0], &summData[StartIPv4], (MaxFragment << 3) + StartIPv4, (MaxFragment << 3));
      }
    }
    else
    {
      return DefragData(Frame, reinterpret_cast<const char*>(IPv4) + lenIP, LengthFrame, LengthIPData);
    }
    return DefragData();
  }
};

typedef std::map<HashForDefragRowsIVv4, DefragRowIPv4> typeDefragDataIPv4;

static typeDefragDataIPv4 DefragDataIPv4;

DefragData DefragIP::AddIPv4(uint32_t NetworkID, const char *Frame, uint32_t LengthFrame, const FilterTraffic::ip4_header* IPv4)
{
  HashForDefragRowsIVv4 Packet(NetworkID, IPv4);
  return DefragDataIPv4[Packet].Build(Frame, LengthFrame, IPv4);
}

void DefragIP::EraseIPv4(uint32_t NetworkID, const FilterTraffic::ip4_header * IPv4)
{
  HashForDefragRowsIVv4 Packet(NetworkID, IPv4);
  auto it_find = DefragDataIPv4.find(Packet);
  if (it_find != DefragDataIPv4.end())
  {
    DefragDataIPv4.erase(it_find);
  }
}

