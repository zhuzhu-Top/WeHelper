//
// Created by 28264 on 2023/7/11.
//
#ifndef WEHELPER_HVSOCKET_H
#define WEHELPER_HVSOCKET_H


#include <libhv/include/hv/TcpClient.h>
#include <future>
#include "../common/ByteBuffer.hpp"

class HVsocket {

    bool connected=false;
    bool disconnected=false;
    bool askReadyComplete=false;
    bool realContentComplete=false;


    hv::TcpClient client;


    std::promise<bool> askReadyPromise;
    std::promise<bool> real_request_promise;
    std::promise<bool> real_request_recv_complete_promise;
//    std::promise<bool> sencond_package_promise;
    std::map<std::string,std::string> askReadyResponse;
    std::map<std::string,std::string> real_response;
    bb::ByteBuffer real_content;
//    bb::ByteBuffer second_content;

    std::function<void(HVsocket* hvSocket,const std::uint8_t*,std::uint32_t)> onMessageCallBack;

    void OnConnected(const hv::SocketChannelPtr& channel);
    void onMessage(const hv::SocketChannelPtr &channel,hv::Buffer *buf);
    void onWriteComplete(const hv::SocketChannelPtr &channel,hv::Buffer *buf);

public:
    HVsocket(int port,std::string host,std::function<void(HVsocket* hvSocket,const std::uint8_t*,std::uint32_t)> callBack);
    std::string StartDownload(std::uint32_t UIN,std::string& aes_key_str,std::string& fileid,std::string& authkey_str);


    bool start_unkonw_header=false;
    bool start_recv_body=false;
    bool start_unkonw_body=false;
    bb::ByteBuffer unkonw_content;
    std::uint32_t totalsize=0x0;

    bool __inline is_allive(){
        return connected && !disconnected;
    }
};

#endif //WEHELPER_HVSOCKET_H
