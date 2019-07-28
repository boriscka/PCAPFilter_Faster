#include <ctime>

#include "../CMDLineParser/cmd_line_parsing.h"
#include "Init.h"
#include "FilterDirect.h"
#include <chrono>

using namespace std::chrono;

int main(int argc, char **argv)
{
  ptime startTime = high_resolution_clock::now();

  try {

    cmd_line::cmd_line_parser parsing_cmd;

    InitParamParser(parsing_cmd);

    if (!parsing_cmd.Init("PcapFilter", "Filter PCAP files", argc, argv))
    {
      parsing_cmd.PrintBuildInfo();
      parsing_cmd.PrintHelpMessage();
      return 0;
    }


    std::string FileNameInput;
    std::string FileNameOutput;
    parsing_cmd.GetParam("--input", FileNameInput);

	  if (FileNameInput.size() < 6) {
		  parsing_cmd.PrintBuildInfo();
		  parsing_cmd.PrintHelpMessage();
		  return 0;
	  }

	  FileNameOutput = FileNameInput.substr(0, FileNameInput.size() - 5) + "_pure.pcap";

    std::string Param;
    Finder::FindDirectTransportPackets = !parsing_cmd.GetParam("--whole-session", Param);

    Request request;
    if (!InitRequest(parsing_cmd, request))
    {
      parsing_cmd.PrintBuildInfo();
      parsing_cmd.PrintHelpMessage();
      return 0;
    }
   
    Statistics stat;

    bool IsFound = FilterDirect(request, stat, FileNameInput, FileNameOutput);

    std::cout << "\nread packets:  " << stat.counterPacketRead << std::endl;
    std::cout << "write packets: " << stat.counterPacketWrite << std::endl << std::flush;
  }
  catch (const std::exception& e) {
    std::cout << std::endl << "[Error] " << e.what() << std::endl;
  }
  catch (...) {
    std::exception_ptr eptr = std::current_exception();
    std::cout << "[Error] some error"; // << eptr._Current_exception();
  }
  ptime endTime = high_resolution_clock::now();

  std::cout << "\nTotal time: " << duration<double>(endTime - startTime).count() << " second(s).\n\n\r";
  return 0;
}
