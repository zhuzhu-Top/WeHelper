cmake_minimum_required(VERSION 3.24)
project(PrintXlog)



file(GLOB sourceFile "*.cpp" "*.h" )

find_library(gum frida-gum ./)
MESSAGE("frida gum -> " ${gum})



add_library(${PROJECT_NAME} SHARED ${sourceFile})

target_link_libraries(${PROJECT_NAME}
        ${gum}
        )







