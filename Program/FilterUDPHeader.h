#ifndef FilterUDPHeader_H
#define FilterUDPHeader_H

#include "FilterIP.h"

namespace FilterTraffic{

PACK_STRUCT_START
struct udp_header {
  uint16_t src_port;    /**< UDP source port. */
  uint16_t dst_port;    /**< UDP destination port. */
  uint16_t dgram_len;   /**< UDP datagram length */
  uint16_t dgram_cksum; /**< UDP datagram checksum */
};
PACK_STRUCT_END

////--IPv4-----=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

#define START_IPV4_UDP       (sizeof(ip4_header) + START_IPV4)
#define START_IPV4_UDP_DATA  (sizeof(udp_header) + START_IPV4_UDP)

}

#endif
