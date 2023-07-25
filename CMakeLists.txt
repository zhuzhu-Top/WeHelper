cmake_minimum_required(VERSION 3.24)
project(WeHelper)

#set(CMAKE_WINDOWS_KITS_ROOT_DIR "D:/Windows Kits/10")
set(CMAKE_CXX_STANDARD 20)
add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")
if (MSVC)
    add_compile_options(
            $<$<CONFIG:>:/MT> #---------|
            $<$<CONFIG:Debug>:/MTd> #---|-- Statically link the runtime libraries
            $<$<CONFIG:Release>:/MT> #--|
    )
    add_compile_options(/EHsc)



endif ()

# 判断架构
if (CMAKE_SIZEOF_VOID_P EQUAL 4)
    message("x86 architecture")
elseif (CMAKE_SIZEOF_VOID_P EQUAL 8)
    message("x64 architecture")
else ()
    message("Unknown architecture")
endif ()

#  将链接选项设置为静态链接，以便将所有静态库打包进程序中。
#set(CMAKE_EXE_LINKER_FLAGS "-static")

file(GLOB frida_all "./frida/*.cpp" "./frida/*.h")
file(GLOB core_all "./core/*.cpp" "./core/*.h")
file(GLOB we_chat_frida
        "./we_chat/*.cpp"
        "./we_chat/*.h"
        )
file(GLOB common
        "./common/*.cpp"
        "./common/*.h"
        "./common/**/*.cpp"
        "./common/**/*.h"
        "./common/**/*.pb.cc"
        )
file(GLOB CryptoTools "./crypto/*.cpp" "./crypto/*.h")

file(GLOB NetMain
        "./include/pugxml/pugiconfig.hpp"
        "./include/pugxml/pugixml.hpp"
        "./include/pugxml/pugixml.cpp"
          "./Net/*.cpp"
          "./Net/*.h"
          "./WS/*.h"
          "./WS/*.cpp"

        )


include_directories(./include/)
include_directories("D:/Code/c_head/OpenSSL-Win32/include")
include_directories("D:/Code/c_head/pb_ins/include")
include_directories("C:/Program Files (x86)/IDA_Pro_7.7/IDA_Pro_7.7/plugins/hexrays_sdk/include")
include_directories("D:/Code/c_cpp/WeHelper/include/libhv/include")

add_subdirectory(include/googletest)
add_subdirectory(include/libhv)
add_subdirectory(include/spdlog-1.x)
add_subdirectory(json)
add_subdirectory(for_test)
add_subdirectory(HookXlog)





# 添加静态库查找路径
list(APPEND CMAKE_LIBRARY_PATH ./lib;D:/Code/c_head/pb_ins/lib)

find_library(frida_core frida-core.lib)
find_library(zlib zlibstaticd.lib)
find_library(openssl openssl.lib)
find_library(libcrypto libcrypto.lib)
find_library(ws2_32 ws2_32.lib)

if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    MESSAGE(STATUS "Build Debug")
    set(protbuf_path "D:/Code/c_head/PB_Ins_Debug/pb/lib/cmake")
else()
    set(protbuf_path "D:/Code/c_head/PB_Ins_Release/pb/lib/cmake")
    MESSAGE(STATUS "Build Not Debug")
endif()

find_package(utf8_range CONFIG HINTS ${protbuf_path})
find_package(absl CONFIG HINTS ${protbuf_path})
find_package(protobuf CONFIG HINTS ${protbuf_path})

include_directories(${protobuf_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

message(STATUS "Using Protocol Buffers ${protobuf_VERSION}")
message(STATUS "is fin protbuf ${protobuf_libprotobuf}")

#MESSAGE(frida_core  > ${frida_core})
MESSAGE(STATUS zlib           > ${zlib})
MESSAGE(STATUS openssl        > ${openssl})
MESSAGE(STATUS libcrypto      > ${libcrypto})
MESSAGE(STATUS ws2_32         > ${ws2_32})





add_executable(${PROJECT_NAME} main.cpp
${frida_all}
${core_all}
${we_chat_frida}
${common}
${CryptoTools}
#        ${ws2_32}
${NetMain}
)



target_include_directories(${PROJECT_NAME} PUBLIC
"${PROJECT_SOURCE_DIR}/json/include"
"${PROJECT_SOURCE_DIR}/include/spdlog-1.x/include"
"${PROJECT_SOURCE_DIR}/include/linhv/include"


)
target_link_libraries(${PROJECT_NAME}
${frida_core}
${zlib}
${openssl}
${libcrypto}

protobuf::libprotobuf
hv_static
gmock
)

get_target_property(LIBRARIES ${PROJECT_NAME} LINK_LIBRARIES)
message("已链接的库: ${LIBRARIES}")



message("CMAKE_BINARY_DIR: ${CMAKE_BINARY_DIR}")


# 移动源目录到目标目录
file(REMOVE_RECURSE ${CMAKE_BINARY_DIR}/html)
file(COPY D:/Code/Vue/wehelper_site/dist DESTINATION ${CMAKE_BINARY_DIR})
file(RENAME ${CMAKE_BINARY_DIR}/dist ${CMAKE_BINARY_DIR}/html)