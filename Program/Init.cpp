#include <vector>

#include "Init.h"
#include "Types.h"

#include "winsock.h"

uint32_t inet_network_ipv4(const char *cp)
{
  uint32_t val, base, n, i;
  char c;
  uint32_t parts[4], *pp = parts;
  int digit;

again:
  val = 0; base = 10; digit = 0;
  if (*cp == '0')
    digit = 1, base = 8, cp++;
  if (*cp == 'x' || *cp == 'X')
    digit = 0, base = 16, cp++;
  while ((c = *cp) != 0)
  {
    if (isdigit(c))
    {
      if (base == 8 && (c == '8' || c == '9'))
        return (INADDR_NONE);
      val = (val * base) + (c - '0');
      cp++;
      digit = 1;
      continue;
    }
    if (base == 16 && isxdigit(c))
    {
      val = (val << 4) + (tolower(c) + 10 - 'a');
      cp++;
      digit = 1;
      continue;
    }
    break;
  }
  if (!digit)
    return (INADDR_NONE);
  if (pp >= parts + 4 || val > 0xff)
    return (INADDR_NONE);
  if (*cp == '.')
  {
    *pp++ = val, cp++;
    goto again;
  }
  while (isspace(*cp))
    cp++;
  if (*cp)
    return (INADDR_NONE);
  if (pp >= parts + 4 || val > 0xff)
    return (INADDR_NONE);
  *pp++ = val;
  n = static_cast<uint32_t>(pp - parts);
  for (val = 0, i = 0; i < n; i++)
  {
    val <<= 8;
    val |= parts[i] & 0xff;
  }
  return (val);
}

std::vector<std::string> split(std::string const & str, char delim)
{
  std::vector<std::string> res;
  std::istringstream iss(str);

  for (std::string temp; std::getline(iss, temp, delim);)
  {
    res.push_back(std::move(temp));
  }

  return res;
}

bool InitParamDataIPv4(const cmd_line::cmd_line_parser& parser, const char* ParamName, PCAP::Uint32Params& params)
{
  std::string Param;
  bool retval = parser.GetParam(ParamName, Param);
  if (retval)
  {
    std::vector<std::string> pars = split(Param, ',');
    for (auto & it : pars) {
      params.push_back( inet_network_ipv4(it.c_str()) );
    }
  }
  return retval;
}

bool InitParamDataPort(const cmd_line::cmd_line_parser& parser, const char* ParamName, PCAP::Uint16Params& params)
{
  std::string Param;
  bool retval = parser.GetParam(ParamName, Param);
  if (retval)
  {
    std::vector<std::string> pars = split(Param, ',');
    uint64_t temp;
    for (auto & it : pars) {
      temp = 0;
      if (parser.tryConvertToInt(it, temp)) {
        params.push_back(static_cast<uint16_t>(temp));
      }
    }
  }
  return retval;
}

// parse string of end points. For example, 10.0.0.1:2020,127.0.0.1:8080
bool InitParamDataIPv4Port(const cmd_line::cmd_line_parser& parser, const char* ParamName, EPParams& params)
{
  std::string Param;
  bool retval = parser.GetParam(ParamName, Param);
  if (retval)
  {
    std::vector<std::string> pars = split(Param, ',');
    
    for (auto& epStr: pars) {
      std::vector<std::string> epV = split(epStr, ':');
      EndPointExt ep;
      uint64_t temp;
      if (epV.size() == 2 && parser.tryConvertToInt(epV[1], temp)) {
        ep.IPv4 = inet_network_ipv4(epV[0].c_str());
        ep.Port = static_cast<uint16_t>(temp);
        params.push_back(std::move(ep));
      }
    }
  }
  return retval;
}

void InitParamParser(cmd_line::cmd_line_parser& parser)
{
  parser.InitParam("-input", "", "<pcap file>", "Input pcap file.", true);
  parser.InitParam("-output", "", "<pcap file>", "Output pcap file.", true);
  parser.InitParam("-is_ip4", "", "<true|false>", "Only IPV4.", false);
  parser.InitParam("-is_ip6", "", "<true|false>", "Only IPV6.", false);
  parser.InitParam("-is_tcp", "", "<true|false>", "Only TCP.", false);
  parser.InitParam("-is_udp", "", "<true|false>", "Only UDP.", false);
  parser.InitParam("-is_sctp", "", "<true|false>", "Only SCTP.", false);
  parser.InitParam("-both_ep", "", "<true|false>", "Find matches of both end points (source and destination).", false);
  parser.InitParam("-drops", "", "<true|false>", "Whether to write dropped unknown packets in separated file.", false);
  parser.InitParam("-luck", "", "<true|false>", "don't search data by halfs into packets (for example, into segments)", false);

  parser.InitParam("-IPv4", "", "<IPv4 NO>[,<IPv4 NO>]*", "Only ip4 addreses (separated by commas).", false);
  parser.InitParam("-port", "", "<port NO>[,<port NO>]*", "Only SRC PORTs (separated by commas).", false);
  parser.InitParam("-eps", "", "<IPv4 NO>:<port NO>[,<IPv4 NO>:<port NO>]*", "find packets by end points (IPv4 and PORT), there are comma is separator.", false);

  parser.InitParam("-DTP", "", "<true|false>", "Direct Transport Packets. Search only direct transport packet by required text data (param -find) to reduce size of found pcap.", false);

  parser.InitParam("-find", "", "<text data>", "Find all packets by \"text data\".", false);
  parser.InitParam("-fi", "", "<text data>", "Same parameter as -find ...", false);

  parser.InitParam("-count", "", "<count packets>", "Stop on <count> packets", false);
  parser.InitParam("-offset", "", "<count packets>", "Start from <offset> packet (-offset 1, it means search from second packet)", false);

  parser.InitParam("-cut_by_count", "", "<count packets>", "Ñut the dump into pieces with the number of packages.", 0);
}

bool InitRequest(const cmd_line::cmd_line_parser & parser, Request & request)
{
  request.flags |= parser.GetParam("-is_ip4") ? SessionRequest::IsIPv4 : SessionRequest::NONE;
  request.flags |= parser.GetParam("-is_ip6") ? SessionRequest::IsIPv6 : SessionRequest::NONE;
  request.flags |= parser.GetParam("-is_tcp") ? SessionRequest::IsTCP : SessionRequest::NONE;
  request.flags |= parser.GetParam("-is_udp") ? SessionRequest::IsUDP : SessionRequest::NONE;
  request.flags |= parser.GetParam("-is_sctp") ? SessionRequest::IsSCTP : SessionRequest::NONE;
  request.flags |= parser.GetParam("-both_ep") ? SessionRequest::BothEP : SessionRequest::NONE;
  request.flags |= parser.GetParam("-drops") ? SessionRequest::ToWriteDrops : SessionRequest::NONE;

  request.flags |= InitParamDataIPv4(parser, "-IPv4", request.addrsIp4) ? SessionRequest::ContainsDesired_ipV4 : SessionRequest::NONE;
  request.flags |= InitParamDataPort(parser, "-port", request.portsUdp) ? SessionRequest::ContainsDesired_Port : SessionRequest::NONE;
  request.flags |= InitParamDataIPv4Port(parser, "-eps", request.eps) ? SessionRequest::ContainsDesired_ipV4Point : SessionRequest::NONE;

  std::string Param;
  request.flags |= parser.GetParam("-fi", Param) ? SessionRequest::ContainsDesired_ContentData : SessionRequest::NONE;
  request.flags |= parser.GetParam("-find", Param) ? SessionRequest::ContainsDesired_ContentData : SessionRequest::NONE;

  uint64_t cntPckts = 0;
  request.packetsCount = parser.GetParam("-count", cntPckts) ? cntPckts : 0;
  request.packetOffset = parser.GetParam("-offset", cntPckts) ? cntPckts : 0;

  if (request.flags.TestFlag(SessionRequest::ContainsDesired_ContentData))
  {
    bool toSearchByHalfs = !parser.GetParam("-luck");
    cmd_line::ParamValuesType Values, Values2;
    parser.GetParams("-fi", Values, toSearchByHalfs);
    parser.GetParams("-find", Values2, toSearchByHalfs);
    request.ContentData.resize(Values.size() + Values2.size());
    std::copy(Values.begin(), Values.end(), request.ContentData.begin());
    std::copy(Values2.begin(), Values2.end(), request.ContentData.begin() + Values.size());
  }
  return true;
}

