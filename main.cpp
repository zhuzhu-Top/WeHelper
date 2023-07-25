/*
 * To build, set up your Release configuration like this:
 *
 * [Runtime Library]
 * Multi-threaded (/MT)
 *
 * Visit https://frida.re to learn more about Frida.
 */
#include "./frida/frida_main.h"
#include "./Net/NetMain.h"
#include "./WS/WS_Main.h"

#include <thread>

#include "spdlog/sinks/stdout_color_sinks.h"

#include "core/WxProtobuf.h"
#include "core/BuildPackage.h"




int main (int argc,char * argv[])
{
    spdlog::set_pattern("[%H:%M:%S %z] [%n] [%^---%l---%$] [thread %t] %v");
    SetConsoleOutputCP(65001);
    spdlog::set_level(spdlog::level::debug);
    NetMain();
//    FridaMain();
    std::jthread fridaThrad(FridaMain);
    std::jthread hvThrad(WS_Main::Init);
//add
    fridaThrad.join();
    hvThrad.join();

    return 0;
}

