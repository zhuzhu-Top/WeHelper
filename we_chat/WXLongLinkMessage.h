//
// Created by 28264 on 2023/5/31.
//

#ifndef WEHELPER_WXLONGLINKMESSAGE_H
#define WEHELPER_WXLONGLINKMESSAGE_H

#include "../include/pub_include.h"
#include "../common/ByteBuffer.hpp"
//bb::ByteBuffer bodyTest(0x200);
//uint8_t payload[]={0xbf,0xba,0x5f,0x63,0x09,0x02,0x17,0xa9,0xaa,0xf6,0x4b,0x16,0x43,0x08,0x0f,0x00,0x00,0x00,0x00,0x41,0x47,0x67,0xf5,0x3b,0x9d,0x00,0x8a,0x04,0x31,0x31,0x00,0x0f,0xe8,0xaa,0xcc,0xe0,0x0d,0x00,0x95,0xe6,0xb8,0x8b,0x02,0x00,0x00,0x00,0x35,0x15,0x66,0xad,0xf9,0x83,0x1d,0x1f,0x18,0x18,0x00,0x16,0xae,0x7e,0x62,0xd1,0x2b,0x67,0xd0,0x56,0x2a,0x43,0xe9,0x55,0xb4,0x0a,0x12,0xd6,0x38,0xed,0x2b,0xa8,0x24,0xd6,0xd4,0x81,0xc9,0x7a,0x2c,0xd3,0xf0,0xb8,0x13,0x09,0x5a,0xef,0x7a,0x67,0x99,0x9b,0x2f,0x4f,0x7d,0xb5,0x77,0x13,0x3d,0x3a,0x5c,0x79,0xbf,0xcc,0xd9,0x9b};
//bodyTest.putBytes(payload, sizeof(payload));
//
//
//WXLongLinkMessage wxLongLinkMessage(0x291,237,bodyTest);
//std::cout<<wxLongLinkMessage.ToByteArray()<<std::endl;


class WXLongLinkMessage {
    uint32_t PacketLength;

    static const  uint16_t HeadLength=0x10;
    static const  uint16_t ProtocalVersion=0x01;


    uint32_t SeqID;   //非重要参数 一直递增  任意修改
    uint32_t Cmd;
    std::unique_ptr<bb::ByteBuffer> Payload;
//    bb::ByteBuffer Payload;  //这个就是包体

    bool IsRequest= false;

public:
    WXLongLinkMessage(uint32_t SeqID,uint32_t Cmd,bb::ByteBuffer Payload);
    WXLongLinkMessage(bb::ByteBuffer& data);

    bb::ByteBuffer ToByteArray();

    void GetPayload(std::unique_ptr<bb::ByteBuffer>& in_Payload){
        in_Payload=Payload->clone();

    }
    uint32_t __inline GetSeqID(){return this->SeqID;}
    uint32_t __inline GetCmd(){return this->Cmd;}

    uint32_t __inline GetGenericCmd(){  //获取原始cmd
        if(IsRequest){
            return Cmd;
        }else{
            return Cmd - 1000000000;
        }
    }
    bool __inline GetIsRequest(){
        return IsRequest;
    }
};


#endif //WEHELPER_WXLONGLINKMESSAGE_H
