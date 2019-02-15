#include "Types.h"

#include <map>
typedef std::map<uint8_t, uint64_t> TransportCounterMap;
typedef std::map<uint16_t, uint64_t> NetworkCounterMap;
bool TrafficAnalysis(uint64_t SizeFrame, const char *Data, const Request& request, Answer& respone, TransportCounterMap* dropsTransportPtr = nullptr, NetworkCounterMap* dropsNetworkPtr = nullptr);