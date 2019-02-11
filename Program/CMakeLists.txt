file(GLOB Program_SRCS *.cpp)
file(GLOB Program_HDRS *.h  )

add_executable(PcapFilter ${Program_SRCS} ${Program_HDRS})

target_link_libraries(PcapFilter PUBLIC pcap_io CMDLineParser)

if (WIN32)
  configure_file(template.vcxproj.user_path_workdir ${CMAKE_CURRENT_BINARY_DIR}/PcapFilter.vcxproj.user)
endif (WIN32)
