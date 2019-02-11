#ifndef FilterTCPHeader_H
#define FilterTCPHeader_H

#include "FilterIP.h"

namespace FilterTraffic
{

  PACK_STRUCT_START
  struct tcp_header
  {
    uint16_t src_port;  /**< TCP source port. */
    uint16_t dst_port;  /**< TCP destination port. */
    uint32_t sent_seq;  /**< TX data sequence number. */
    uint32_t recv_ack;  /**< RX data acknowledgement sequence number. */
    uint8_t  lenheader;
    uint8_t  tcp_flags; /**< TCP flags */
    uint16_t rx_win;    /**< RX flow control window. */
    uint16_t cksum;     /**< TCP checksum. */
    uint16_t tcp_urp;   /**< TCP urgent pointer, if any. */
  };
  PACK_STRUCT_END


    //  union TCPFLUGS
    //  {
    //    struct
    //    {
    //#if defined(IS_BIG_ENDIAN)
    //      uint16_t
    //        doff : 4,//Зарезервировано
    //        res1 : 4,//Длина заголовка
    //        fin : 1,//(англ. final, бит) — флаг, будучи установлен, указывает на завершение соединения (англ. FIN bit used for connection termination).
    //        syn : 1,//Синхронизация номеров последовательности (англ. Synchronize sequence numbers)
    //        rst : 1,//Оборвать соединения, сбросить буфер (очистка буфера) (англ. Reset the connection)
    //        psh : 1,//(англ. Push function) инструктирует получателя протолкнуть данные, накопившиеся в приёмном буфере, в приложение пользователя
    //        ack : 1,//Поле «Номер подтверждения» задействовано (англ. Acknowledgement field is significant)
    //        urg : 1,//Поле «Указатель важности» задействовано (англ. Urgent pointer field is significant)
    //        ece : 1,//Поле «Эхо ECN» — указывает, что данный узел способен на ECN (явное уведомление перегрузки) и для указания отправителю о перегрузках в сети
    //        cwr : 1;//Поле «Окно перегрузки уменьшено» — флаг установлен отправителем, чтобы указать, что получен пакет с установленным флагом ECE
    //                //      cwr:1,//Поле «Окно перегрузки уменьшено» — флаг установлен отправителем, чтобы указать, что получен пакет с установленным флагом ECE
    //                //      ece:1,//Поле «Эхо ECN» — указывает, что данный узел способен на ECN (явное уведомление перегрузки) и для указания отправителю о перегрузках в сети
    //                //      urg:1,//Поле «Указатель важности» задействовано (англ. Urgent pointer field is significant)
    //                //      ack:1,//Поле «Номер подтверждения» задействовано (англ. Acknowledgement field is significant)
    //                //      psh:1,//(англ. Push function) инструктирует получателя протолкнуть данные, накопившиеся в приёмном буфере, в приложение пользователя
    //                //      rst:1,//Оборвать соединения, сбросить буфер (очистка буфера) (англ. Reset the connection)
    //                //      syn:1,//Синхронизация номеров последовательности (англ. Synchronize sequence numbers)
    //                //      fin:1;//(англ. final, бит) — флаг, будучи установлен, указывает на завершение соединения (англ. FIN bit used for connection termination).
    //#else
    //      uint16_t
    //        res1 : 4,//Длина заголовка
    //        doff : 4,//Зарезервировано
    //        cwr : 1,//Поле «Окно перегрузки уменьшено» — флаг установлен отправителем, чтобы указать, что получен пакет с установленным флагом ECE
    //        ece : 1,//Поле «Эхо ECN» — указывает, что данный узел способен на ECN (явное уведомление перегрузки) и для указания отправителю о перегрузках в сети
    //        urg : 1,//Поле «Указатель важности» задействовано (англ. Urgent pointer field is significant)
    //        ack : 1,//Поле «Номер подтверждения» задействовано (англ. Acknowledgement field is significant)
    //        psh : 1,//(англ. Push function) инструктирует получателя протолкнуть данные, накопившиеся в приёмном буфере, в приложение пользователя
    //        rst : 1,//Оборвать соединения, сбросить буфер (очистка буфера) (англ. Reset the connection)
    //        syn : 1,//Синхронизация номеров последовательности (англ. Synchronize sequence numbers)
    //        fin : 1;//(англ. final, бит) — флаг, будучи установлен, указывает на завершение соединения (англ. FIN bit used for connection termination).
    //                //    fin:1,//(англ. final, бит) — флаг, будучи установлен, указывает на завершение соединения (англ. FIN bit used for connection termination).
    //                //    syn:1,//Синхронизация номеров последовательности (англ. Synchronize sequence numbers)
    //                //    rst:1,//Оборвать соединения, сбросить буфер (очистка буфера) (англ. Reset the connection)
    //                //    psh:1,//(англ. Push function) инструктирует получателя протолкнуть данные, накопившиеся в приёмном буфере, в приложение пользователя
    //                //    ack:1,//Поле «Номер подтверждения» задействовано (англ. Acknowledgement field is significant)
    //                //    urg:1,//Поле «Указатель важности» задействовано (англ. Urgent pointer field is significant)
    //                //    ece:1,//Поле «Эхо ECN» — указывает, что данный узел способен на ECN (явное уведомление перегрузки) и для указания отправителю о перегрузках в сети
    //                //    cwr:1;//Поле «Окно перегрузки уменьшено» — флаг установлен отправителем, чтобы указать, что получен пакет с установленным флагом ECE
    //#endif
    //    };
    //    uint16_t AllFlugs;
    //  };

    static_assert(sizeof(tcp_header), "sizeof(tcp_header) != 160!!!");
    ////--IPv4-----=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

#define START_IPV4_TCP       (sizeof(ip4_header) + START_IPV4)
#define IPv4_StartTCPOptions (START_IPV4_TCP     + 20)
#define START_IPV6_TCP       (sizeof(ip6_header) + START_IPV6)
#define IPv6_StartTCPOptions (START_IPV6_TCP     + 20)

}

#endif
