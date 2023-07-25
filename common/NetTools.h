//
// Created by 28264 on 2023/6/2.
//

#ifndef WEHELPER_NETTOOLS_H
#define WEHELPER_NETTOOLS_H
#pragma once
#include <iostream>
#include <vector>
#include <iomanip>

class NetTools{

public:
    static void GetIPAddresses(const std::string& hostname,std::vector<std::string>& ipv4_address,std::vector<std::string>& ipv6_address);
};



#endif //WEHELPER_NETTOOLS_H
