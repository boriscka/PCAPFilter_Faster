#ifndef FilterSCTPHeader_H
#define FilterSCTPHeader_H

namespace FilterTraffic{

  enum class SCTPProtocolState : uint8_t
  {
    CLOSED,            //Начальное состояние узла. Фактически фиктивное
    COOKIE_WAIT,
    COOKIE_ECHOED,
    COOKIE_ECHOED2,
    ESTABLISHED,       //Соединение установлено, идёт передача данных
    SHUTDOWN_ACK_SENT,
    SHUTDOWN_PENDING,
    SHUTDOWN_SENT,
    SHUTDOWN_RECEIVED,
  };

//#define SizeStateCooke_DATA (16 + sizeof(uint64_t) + 120)
#define SizeStateCooke_DATA (16)

#define START_IPV4_SCTP       (sizeof(ip4_header) + START_IPV4)
#define START_IPV6_SCTP       (sizeof(ip6_header) + START_IPV6)

  enum class SCTPMessageType
  {
    Unknown,
    INIT,
    INIT_ACK,
    COOKIE_ECHO,
    COOKIE_ACK,
    DATA,
    SACK,
    SACK_AND_DATA,
    SHUTDOWN,
    SHUTDOWN_ACK,
    SHUTDOWN_COMPLETE
  };


//SCTP Header
PACK_STRUCT_START
struct sctp_header
{
  uint16_t src_port; /**< Source port. */
  uint16_t dst_port; /**< Destin port. */
  uint32_t tag;      /**< Validation tag. */
  uint32_t cksum;    /**< Checksum. */
}
PACK_STRUCT_END;

//SCTP Header INIT
PACK_STRUCT_START
struct sctp_header_init_ipv4
{
  uint8_t  ChunkType;// Chunk type INIT (1)
  uint8_t  ChunkFlags;// Chunk flags: 0x00
  uint16_t ChunkLength;// Chunk length: 84
    uint32_t InitiateTag;
    uint32_t ARWND;//Advertised Receiver Window Credit (a_rwnd)
    uint16_t NumberOfOutbound;//Number of Outbound Streams
    uint16_t NumberOfInbound;//Number of Inbound Streams
    uint32_t InitialTSN;

    uint16_t TypeIPV4_1;//0x0005
    uint16_t TypeIPV4_1_Length;//8
    uint32_t IPV4_1;

    uint16_t SupportedAddressTypes;//(0x000c)
    uint16_t SupportedAddressTypes_Length;//8
    uint16_t SATIPV6;//    Supported address type: IPv6 address (6)
    uint16_t SATIPV4;//    Supported address type: IPv4 address (5)

    uint16_t ECN;       // Parameter type: ECN (0x8000)
    uint16_t ECN_Length;// Parameter length: 4

    uint16_t ForwardTSN;       // arameter type: Forward TSN supported (0xc000)
    uint16_t ForwardTSN_Length;// Parameter length: 4

}
PACK_STRUCT_END;

//SCTP Header INIT
PACK_STRUCT_START
struct sctp_header_init_ipv6
{
  uint8_t  ChunkType;// Chunk type INIT (1)
  uint8_t  ChunkFlags;// Chunk flags: 0x00
  uint16_t ChunkLength;// Chunk length: 104
  uint32_t InitiateTag;
  uint32_t ARWND;//Advertised Receiver Window Credit (a_rwnd)
  uint16_t NumberOfOutbound;//Number of Outbound Streams
  uint16_t NumberOfInbound;//Number of Inbound Streams
  uint32_t InitialTSN;

  uint16_t TypeIPV6;//0x0005
  uint16_t TypeIPV6_Length;//8
  IPv6Addres IPV6;

  uint16_t SupportedAddressTypes;//(0x000c)
  uint16_t SupportedAddressTypes_Length;//8
  uint16_t SATIPV6;//    Supported address type: IPv6 address (6)
  uint16_t SATIPV4;//    Supported address type: IPv4 address (5)

  uint16_t ECN;       // Parameter type: ECN (0x8000)
  uint16_t ECN_Length;// Parameter length: 4

  uint16_t ForwardTSN;       // arameter type: Forward TSN supported (0xc000)
  uint16_t ForwardTSN_Length;// Parameter length: 4

}
PACK_STRUCT_END;


//SCTP Header INIT_ACK
PACK_STRUCT_START
struct sctp_header_init_ack_ipv4
{
  uint8_t  ChunkType;// Chunk type INIT_ACK (2)
  uint8_t  ChunkFlags;// Chunk flags: 0x00
  uint16_t ChunkLength;// Chunk length: 308
  uint32_t InitiateTag;
  uint32_t ARWND;//Advertised Receiver Window Credit (a_rwnd)
  uint16_t NumberOfOutbound;//Number of Outbound Streams
  uint16_t NumberOfInbound;//Number of Inbound Streams
  uint32_t InitialTSN;

  uint16_t TypeIPV4_1;// Chunk type IPv4 address (0x0005)
  uint16_t TypeIPV4_1_Length;//8
  uint32_t IPV4_1;

  uint16_t SupportedAddressTypes;//(0x000c)
  uint16_t SupportedAddressTypes_Length;//8
  uint16_t SATIPV6;//    Supported address type: IPv6 address (6)
  uint16_t SATIPV4;//    Supported address type: IPv4 address (5)

  uint16_t StateCooke;       // Chunk type: ECN (0x0007)
  uint16_t StateCooke_Length;// Chunk length: 264
  uint8_t  StateCooke_DATA[SizeStateCooke_DATA];

  uint16_t ECN;       // Chunk type: ECN (0x8000)
  uint16_t ECN_Length;// Chunk length: 4

  uint16_t ForwardTSN;       // Chunk type: Forward TSN supported (0xc000)
  uint16_t ForwardTSN_Length;// Chunk length: 4

}
PACK_STRUCT_END;

//SCTP Header INIT_ACK
PACK_STRUCT_START
struct sctp_header_init_ack_ipv6
{
  uint8_t  ChunkType;// Chunk type INIT_ACK (2)
  uint8_t  ChunkFlags;// Chunk flags: 0x00
  uint16_t ChunkLength;// Chunk length: 308
  uint32_t InitiateTag;
  uint32_t ARWND;//Advertised Receiver Window Credit (a_rwnd)
  uint16_t NumberOfOutbound;//Number of Outbound Streams
  uint16_t NumberOfInbound;//Number of Inbound Streams
  uint32_t InitialTSN;

  uint16_t TypeIPV6;// Chunk type IPv4 address (0x0005)
  uint16_t TypeIPV6_Length;//8
  IPv6Addres IPV6;

  uint16_t SupportedAddressTypes;//(0x000c)
  uint16_t SupportedAddressTypes_Length;//8
  uint16_t SATIPV6;//    Supported address type: IPv6 address (6)
  uint16_t SATIPV4;//    Supported address type: IPv4 address (5)

  uint16_t StateCooke;       // Chunk type: ECN (0x0007)
  uint16_t StateCooke_Length;// Chunk length: 264
  uint8_t  StateCooke_DATA[SizeStateCooke_DATA];

  uint16_t ECN;       // Chunk type: ECN (0x8000)
  uint16_t ECN_Length;// Chunk length: 4

  uint16_t ForwardTSN;       // Chunk type: Forward TSN supported (0xc000)
  uint16_t ForwardTSN_Length;// Chunk length: 4

}
PACK_STRUCT_END;


//SCTP Header COOKIE_ECHO
PACK_STRUCT_START
struct sctp_header_cooke_echo
{
  uint8_t Cooke;       // Chunk type: COOKE_ECHO (10)
  uint8_t CookeFlugs;  // Chunk Flugs (0)
  uint16_t Cooke_Length;// Chunk length
  uint8_t  Cooke_DATA[SizeStateCooke_DATA];
}
PACK_STRUCT_END;


//SCTP Header COOKIE_ECHO_ACK
PACK_STRUCT_START
struct sctp_header_cooke_echo_ack
{
  uint8_t Cooke;       // Chunk type: COOKE_ECHO_ACK (11)
  uint8_t CookeFlugs;  // Chunk Flugs (0)
  uint16_t Cooke_Ack_Length;// Chunk length: 4
}
PACK_STRUCT_END;

//SCTP Header DATA
PACK_STRUCT_START
struct sctp_header_cooke_data
{
  uint8_t CookeDATA;  // Chunk type: DATA (0)
  uint8_t CookeFlugs; // Chunk Flugs (7)
  uint16_t Cooke_DATA_Length;// Chunk length: ? + DATA_SIZE
  uint32_t TSN_DATA;// Transmission sequence number
  uint16_t SI; // Stream identifier 0x0000
  uint16_t SSN;// Stream sequence number 0x0000
  uint32_t PPI;// Payload protocol identifier

}
PACK_STRUCT_END;

//SCTP Header SACK
PACK_STRUCT_START
struct sctp_header_cooke_sack
{
  uint8_t CookeACK;  // Chunk type: SACK (3)
  uint8_t CookeFlugs; // Chunk Flugs (0)
  uint16_t Cooke_ACK_Length;// Chunk length: 16
  uint32_t TSN_ACK;//Cumulative TSN ACK: 2569608497
  uint32_t A_RWND;// Advertised receiver window credit (a_rwnd): 65042
  uint16_t N_GAP_ACK_Block;//  Number of gap acknowledgement blocks: 0
  uint16_t N_DUP_TSNs;// Number of duplicated TSNs: 0

}
PACK_STRUCT_END;

PACK_STRUCT_START
struct sctp_header_cooke_shutdown
{
  uint8_t CookeSHUTDOWN;  // Chunk type: SHUTDOWN (7)
  uint8_t CookeFlugs; // Chunk Flugs (0)
  uint16_t Cooke_SHUTDOWN_Length;// Chunk length: 8
  uint32_t TSN_SHUTDOWN;//Cumulative TSN ACK: 2569608497

}
PACK_STRUCT_END;

PACK_STRUCT_START
struct sctp_header_cooke_shutdown_ack
{
  uint8_t CookeSHUTDOWN_ACK;  // Chunk type: SHUTDOWN_ACK (8)
  uint8_t CookeFlugs; // Chunk Flugs (0)
  uint16_t Cooke_ACK_Length;// Chunk length: 4
}
PACK_STRUCT_END;


PACK_STRUCT_START
struct sctp_header_cooke_shutdown_complete
{
  uint8_t CookeSHUTDOWN_COMPLETE;  // Chunk type: SHUTDOWN_COMPLETE (14)
  uint8_t CookeFlugs; // Chunk Flugs (0)
  uint16_t Cooke_ACK_Length;// Chunk length: 4
}
PACK_STRUCT_END;

}//namespace FilterTraffic

#endif //FilterSCTPHeader_H
