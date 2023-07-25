//
// Created by 28264 on 2023/7/12.
//
#include "WsBridge.h"
//#include "../core/BuildPackage.h"
#include "../common/HVSocket.h"
#include "WeChatBridge.h"
#include "../common/Utils.h"



//#include <libhv/include/hv/TcpClient.h>





std::string
WsBridge::WX_DonwloadImg( std::string& aes_key_str,std::string& fileid) {
    std::promise<bb::ByteBuffer> rpc_recv_complete_promise;

    if(!weChatBridge->dns_Initialized){ //如果dns没初始化,就返回先初始化dns
        return "need init dns";
    }

    std::string authkey_str;
//    std::uint8_t authkey[] =  {0x30,0x3e,0x02,0x01,0x01,0x04,0x37,0x30,0x35,0x02,0x01,0x01,0x02,0x01,0x01,0x02,
//                               0x04,0x6f,0x6f,0x63,0xae,0x02,0x01,0x00,0x02,0x01,0x00,0x02,0x04,0x8f,0x87,0x13,
//                               0x70,0x02,0x03,0x2f,0x77,0xf7,0x02,0x04,0x9b,0xe1,0x2e,0x70,0x02,0x04,0x9d,0xe1,
//                               0x2e,0x70,0x02,0x04,0x65,0x00,0x4d,0x81,0x02,0x04,0x83,0xc7,0x4a,0xa8,0x04,0x00
//                             };
//    std::string authkey="303e0201010437303502010102010102046f6f63ae02010002010002045285137002032f56c3020429bead2702042abead27020465025a6202045bc77c7f0400";
    std::string& authkey= weChatBridge->dns_authkey_str;

    authkey_str.resize(authkey.size()/2+1);
    authkey_str.resize(Utils::string2byte(authkey,(std::uint8_t*)authkey_str.data()));

//    HVsocket hvSocket(8080, "120.233.36.17",
    HVsocket hvSocket(8080, weChatBridge->dns_server_ip,
                      std::bind([&rpc_recv_complete_promise](HVsocket* hvSocket,const std::uint8_t* data,std::uint32_t data_size){


                      },std::placeholders::_1,std::placeholders::_2,std::placeholders::_3));



//    std::string  content =  hvSocket.StartDownload(weChatBridge->G_UIN,aes_key_str,fileid,weChatBridge->authkey_str);
    std::string  content =  hvSocket.StartDownload(weChatBridge->G_UIN,aes_key_str,fileid,authkey_str);

//    std::string tmp_str = content.getString();
//    WxProtobuf::Parse_CDNDnsResponse();

    return std::move(content);
}

