//
// Created by 28264 on 2023/6/2.
//
#include "./NetTools.h"


#include <winsock2.h> // 先包含winsock2.h
#include <ws2tcpip.h> // 再包含ws2tcpip.h



void NetTools::GetIPAddresses(const std::string &hostname, std::vector<std::string> &ipv4_address,
                              std::vector<std::string> &ipv6_address) {


    struct addrinfo* result = nullptr;
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;    // 支持 IPv4 和 IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // 调用 getaddrinfo 获取地址信息
    int status = getaddrinfo(hostname.c_str(), nullptr, &hints, &result);
    if (status != 0) {
        std::cerr << "getaddrinfo failed: " << gai_strerror(status) << std::endl;
    }

    // 遍历地址信息链表，获取 IP 地址
    for (struct addrinfo* address = result; address != nullptr; address = address->ai_next) {
        char ipAddress[INET6_ADDRSTRLEN];
        if (address->ai_family == AF_INET) { // IPv4
            struct sockaddr_in* ipv4 = reinterpret_cast<struct sockaddr_in*>(address->ai_addr);
            inet_ntop(AF_INET, &(ipv4->sin_addr), ipAddress, INET6_ADDRSTRLEN);
            ipv4_address.push_back(ipAddress);
        } else if (address->ai_family == AF_INET6) { // IPv6
            struct sockaddr_in6* ipv6 = reinterpret_cast<struct sockaddr_in6*>(address->ai_addr);
            inet_ntop(AF_INET6, &(ipv6->sin6_addr), ipAddress, INET6_ADDRSTRLEN);
            ipv6_address.push_back(ipAddress);
        }
    }

    // 释放地址信息链表内存
    freeaddrinfo(result);

    return;
}
