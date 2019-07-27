#include <ctime>

#include "../CMDLineParser/cmd_line_parsing.h"
#include "Init.h"
#include "FilterDirect.h"

std::time_t OutTime(const char* Message = nullptr)
{
  std::time_t t = std::time(0);   // get time now
  std::tm* now = std::localtime(&t);
  if (Message != nullptr) std::cout << Message << " ";
  std::cout << 1900 + now->tm_year;
  std::cout << ".";
  //month
  if (now->tm_mon < 9)
    std::cout << "0" << 1 + now->tm_mon << ".";
  else
    std::cout << (1 + now->tm_mon) << ".";
  //day
  if (now->tm_mday < 10)
    std::cout << "0" << now->tm_mday << " ";
  else
    std::cout << now->tm_mday << " ";
  //hour
  if (now->tm_hour < 10)
    std::cout << "0" << now->tm_hour << ":";
  else
    std::cout << now->tm_hour << ":";
  //min
  if (now->tm_min < 10)
    std::cout << "0" << now->tm_min << ":";
  else
    std::cout << now->tm_min << ":";
  //sec
  if (now->tm_sec < 10)
    std::cout << "0" << now->tm_sec;
  else
    std::cout << now->tm_sec;

  std::cout << std::endl;
  return t;
}

int main(int argc, char **argv)
{
  std::time_t startTime = OutTime("Start program");

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

    std::cout << "Count read packets:  " << stat.counterPacketRead << std::endl;
    std::cout << "Count write packets: " << stat.counterPacketWrite << std::endl << std::flush;
  }
  catch (const std::exception& e) {
    std::cout << std::endl << "[Error] " << e.what() << std::endl;
  }
  catch (...) {
    std::exception_ptr eptr = std::current_exception();
    std::cout << "[Error] some error"; // << eptr._Current_exception();
  }
  std::time_t endTime = OutTime("End program");

  std::cout << "Working time passed: " << std::difftime(endTime, startTime) << " second(s).\n";
  return 0;
}
