//
// Created by 28264 on 2023/6/23.
//

#ifndef WEHELPER_WXSHORTLINKMESSAGE_H
#define WEHELPER_WXSHORTLINKMESSAGE_H
#include "../include/pub_include.h"
#include "../common/ByteBuffer.hpp"

class WXShortLinkMessage {
    class WeChatBridge* weChatBridge;

    bb::ByteBuffer tlsInnerBody; //用于tls加密的包
    bb::ByteBuffer sendPackage;

    std::uint32_t CreateClientHello(bb::ByteBuffer& clientHello);

    bb::ByteBuffer resp_body;
    bb::ByteBuffer hash_data;
    std::vector<bb::ByteBuffer> vec_packages;



public:
    WXShortLinkMessage(std::string host,std::string cgiurl,bb::ByteBuffer& data);



    void SetWechatBridge(class WeChatBridge* weChatBridge){
        this->weChatBridge=weChatBridge;
    }
    void ShortLinkPack();
    bb::ByteBuffer ShortLinkUnPack();

    void Parse();
    bb::ByteBuffer Post();
};


#endif //WEHELPER_WXSHORTLINKMESSAGE_H
