//
// Created by 28264 on 2023/6/12.
//

#ifndef WEHELPER_WS_SERVER_H
#define WEHELPER_WS_SERVER_H
#include "../we_chat/WsBridge.h"
#include "libhv/include/hv/WebSocketServer.h"


enum SocketType{
     Init = 1,
    SendMsg = 2,

};





class WS_Server {
    hv::HttpService http;
    hv::WebSocketServer server;


    void onopen(const WebSocketChannelPtr& channel, const HttpRequestPtr& req);
    void onmessage(const WebSocketChannelPtr& channel, const std::string& msg);
    void onclose(const WebSocketChannelPtr& channel);

    static void on_open(const WebSocketChannelPtr& channel, const HttpRequestPtr& req);
public:
    WS_Server();

    void run();



    std::map<std::string,WebSocketChannelPtr> Connections;

    uint32_t DEFAULT_PORT=8080;
    std::string DEFAULT_ConfigFileNmae="config.ini";
};


#endif //WEHELPER_WS_SERVER_H
