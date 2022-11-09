cmake_minimum_required(VERSION 3.0.0)
project(tunonraw VERSION 0.1.0)


macro(list_source_directories srcs)
    unset(tmp)
    foreach(dir ${ARGN})
        aux_source_directory(${dir} tmp)
    endforeach()
    set(${srcs} ${tmp})
    #list(FILTER ${srcs} EXCLUDE REGEX ".*_test\\.c")
endmacro()

########### hv lib start ###########
list_source_directories(HV_SRC hv hv/base/ hv/event/ hv/ssl/)
add_library(hv ${HV_SRC})
target_compile_definitions(hv PUBLIC HV_STATICLIB)
target_include_directories(hv PUBLIC hv hv/base/ hv/ssl hv/event/)
########### hv lib end ###########

########### tor lib start ###########

list_source_directories(TORSRC tor)
add_library(tor ${TORSRC})
########### tor lib end ###########


add_executable(test_udpserver 
    test_udpserver.c

)

target_link_libraries(test_udpserver hv tor)

######### test udp client ##########
add_executable(test_udpclient
    test_udpclient.c

)
target_link_libraries(test_udpclient hv tor)