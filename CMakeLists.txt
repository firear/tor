cmake_minimum_required(VERSION 2.8.12)
project(tunonraw)

if (${CMAKE_VERSION} VERSION_LESS 3.1)
	set(CMAKE_C_FLAGS "-std=c99")
else()
	set(CMAKE_C_STANDARD 99)
	set(CMAKE_C_STANDARD_REQUIRED True)
endif()

macro(list_source_directories srcs)
    unset(tmp)
    foreach(dir ${ARGN})
        aux_source_directory(${dir} tmp)
    endforeach()
    set(${srcs} ${tmp})
    #list(FILTER ${srcs} EXCLUDE REGEX ".*_test\\.c")
endmacro()

if(WIN32)
add_compile_options(/utf-8 -DBPF_MAJOR_VERSION)
include_directories("D:/proj/npcap-sdk-1.13/Include")
link_directories("D:/proj/npcap-sdk-1.13/Lib/x64")
set(LIBPCAP wpcap)
else()
set(LIBPCAP pcap)
endif(WIN32)

#-----------------------------

# include_directories(kernel ssl .)

# list_source_directories(TINYWF_SRCS kernel ssl)

# add_library(kernel ${TINYWF_SRCS})

#-----------------------------


########### tor lib start ###########

list_source_directories(TORSRC tor)
add_library(tor ${TORSRC}
kernel/debug.c
kernel/debug.h
kernel/thrqueue_cs.c
kernel/thrqueue.h
kernel/hbase.c
kernel/rbtree.c
kernel/htime.c
kernel/hsocket.c
)
target_include_directories(tor PUBLIC kernel ssl)
# target_link_libraries(tor PUBLIC kernel)
target_compile_definitions(tor PUBLIC HV_STATICLIB)
########### tor lib end ###########


add_executable(test_udpserver 
    test_udpserver.c

)

target_link_libraries(test_udpserver tor pthread)

######### test udp client ##########
add_executable(test_udpclient
    test_udpclient.c

)
target_link_libraries(test_udpclient tor pthread)


######### test raw client ##########
add_executable(test_tor
    test_tor.c
)
target_link_libraries(test_tor tor ${LIBPCAP} pthread)

# -------

add_executable(udp2raw
    udp2raw.c
)
target_link_libraries(udp2raw tor ${LIBPCAP} pthread)
#