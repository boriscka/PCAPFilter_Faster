file(GLOB Program_SRCS *.c *.cpp)
file(GLOB Program_HDRS *.h)

add_library(pcap_io STATIC ${Program_SRCS} ${Program_HDRS})

if (WIN32)
  set_property(TARGET pcap_io PROPERTY FOLDER "Tools")
endif (WIN32)