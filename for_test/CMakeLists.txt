cmake_minimum_required(VERSION 3.24)
project(ForTest)

enable_testing()

add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")

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


file(GLOB sourceFile "*.cpp" )
file(GLOB common_sourceFile "${CMAKE_SOURCE_DIR}/common/*.cpp" "${CMAKE_SOURCE_DIR}/common/*.h" )

add_executable(${PROJECT_NAME}
        ${sourceFile}
        "${CMAKE_SOURCE_DIR}/common/ProtobufHelper.cpp"
        "${CMAKE_SOURCE_DIR}/common/ByteBuffer.hpp"
        "${CMAKE_SOURCE_DIR}/common/ByteBuffer.cpp"

        )

#message("当前项目的顶层路径：${CMAKE_SOURCE_DIR}")
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/include/googletest/googletest/include)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/include/googletest/googlemock/include)

target_include_directories(${PROJECT_NAME} PUBLIC
        "${PROJECT_SOURCE_DIR}/../json/include"
        "${PROJECT_SOURCE_DIR}/../include/spdlog-1.x/include"
        )
target_link_libraries(${PROJECT_NAME} PRIVATE gtest gtest_main protobuf::libprotobuf)

add_dependencies(${PROJECT_NAME} gtest gtest_main )






