#ifndef Init_h
#define Init_h

#include "../CMDLineParser/cmd_line_parsing.h"
#include "../PCAP_DiskIO/PCAP_Common.h"

#include "Types.h"

void InitParamParser(cmd_line::cmd_line_parser& parser);

bool InitRequest(const cmd_line::cmd_line_parser& parser, Request& request);

#endif//Init_h
