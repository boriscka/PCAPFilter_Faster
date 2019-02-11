#ifndef FilterIP_H
#define FilterIP_H

#include <stdint.h>

#include "FilterDefines.h"

namespace FilterTraffic{

union ip4_addr{
  uint32_t ip_32;
  uint8_t ip8[4];
};

/**
 * IPv4 Header
 */
PACK_STRUCT_START
struct ip4_header {
        uint8_t  version_ihl;		/**< version and header length */
        uint8_t  type_of_service;	/**< type of service */
        uint16_t total_length;		/**< length of packet */
        uint16_t packet_id;		/**< packet ID */
        uint16_t fragment_offset;	/**< fragmentation offset */
        uint8_t  time_to_live;		/**< time to live */
        uint8_t  next_proto_id;		/**< protocol ID */
        uint16_t hdr_checksum;		/**< header checksum */
        ip4_addr src_addr;		/**< source address */
        ip4_addr dst_addr;		/**< destination address */
};
PACK_STRUCT_END

typedef uint8_t IPv6Addres[16];

/**
 * IPv6 Header
 */
PACK_STRUCT_START
struct ip6_header {
        uint32_t vtc_flow;     /**< IP version, traffic class & flow label. */
        uint16_t payload_len;  /**< IP packet length - includes sizeof(ip_header). */
        uint8_t  proto;        /**< Protocol, next header. */
        uint8_t  hop_limits;   /**< Hop limits. */
        IPv6Addres  src_addr; /**< IP address of source host. */
        IPv6Addres  dst_addr; /**< IP address of destination host(s). */
};
PACK_STRUCT_END

#define START_MAC_DSN         0
#define START_MAC_SRC         6
#define START_TYPE_FRAME      12

#define START_IPV4            14
#define END_IPV4              14 + sizeof(ip4_header)
#define START_IPV6            14
#define END_IPV6              14 + sizeof(ip6_header)

}

#endif
