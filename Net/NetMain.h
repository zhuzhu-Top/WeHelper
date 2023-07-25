//
// Created by 28264 on 2023/6/2.
//

#ifndef WEHELPER_NETMAIN_H
#define WEHELPER_NETMAIN_H

#include "../common/NetTools.h"
#include "spdlog/spdlog.h"
//#include <KnownFolders.h>
//#include <ShlObj_core.h>


using namespace std;
class NetConfig{

public:

    static const std::string long_weixin_qq_com;
    static const std::string szlong_weixin_qq_com;
    static const std::string ShortLink_host_name;
    static std::vector<std::string> LongLink_ipv4_address;
    static std::vector<std::string> LongLink_ipv6_address;



    static bool IsLongLink(string& IP,uint32_t port);


    static std::string requestJsScript();
};

void NetMain();

#endif //WEHELPER_NETMAIN_H
