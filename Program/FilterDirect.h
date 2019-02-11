#ifndef FILTERDIRECT_H
#define FILTERDIRECT_H

#include "Types.h"

bool FilterDirect(Request& request, Statistics& stat, std::string FileNameInput, std::string FileNameOutput);

struct Finder{
  static bool FindDirectTransportPackets;
};

#endif // !FILTERDIRECT_H
