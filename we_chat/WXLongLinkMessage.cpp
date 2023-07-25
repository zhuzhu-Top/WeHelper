//
// Created by 28264 on 2023/5/31.
//

#include "WXLongLinkMessage.h"
#include "WXCGIUrl.h"


void Log_WXLongLinkMessage(bool& IsRequest, uint32_t SeqID,uint32_t reqID,uint32_t PacketLength ){
    if(reqID <  1000000000){
        IsRequest= true;
    }else{
        IsRequest= false;
        reqID=reqID-1000000000;
    }

    spdlog::info("[{}] WXLongLinkMessage SeqID: {},Cmd: {} {},PacketLength: {}",
                    IsRequest ? "Request" : "Response",
                        SeqID,
                 reqID ,
                 ReqId2StringFun(reqID),
                        PacketLength);
}
WXLongLinkMessage::WXLongLinkMessage(uint32_t SeqID,
                                     uint32_t Cmd,
                                     bb::ByteBuffer Payload) : SeqID(SeqID), Cmd(Cmd) {
    this->Payload=Payload.clone();

    PacketLength=0x10+Payload.size();
    Log_WXLongLinkMessage(IsRequest,SeqID,Cmd,PacketLength);
}

bb::ByteBuffer WXLongLinkMessage::ToByteArray() {
    bb::ByteBuffer bb;

    bb.putIntBE(PacketLength);          // 4字节封包长度(含包头)，可变

    bb.putShortBE(HeadLength);          // 2字节表示头部长度，固定值，0x10
    bb.putShortBE(ProtocalVersion);     // 2字节表示协议版本，固定值，0x01

    bb.putIntBE(Cmd);                      // 4字节cmdid，可变
    bb.putIntBE(SeqID);                   // 4字节封包编号，可变
    bb.put(Payload.get());
    return bb;
}
/// 直接传入AES GCM 解密后的内容
/// \param data
WXLongLinkMessage::WXLongLinkMessage(bb::ByteBuffer& data) {
    if (data.size()<0x10){
        SeqID=0;
        Cmd=0;
        return;
    }
    Payload=data.clone();
    this->PacketLength= data.getIntBE();   //算包头0x10          //4
    uint32_t tmp_HeadVersion = data.getShort();                 //2
    uint32_t tmp_ProtocalVersion = data.getShort();             //2
    Cmd=data.getIntBE();                                        //4
    SeqID=data.getIntBE();                                      //4


//    this->Payload= bb::ByteBuffer(data);
    uint8_t head_byte[0x10]={0};
    Payload->getBytes(head_byte,0x10);
    spdlog::info("mmtls head -> {}",   fmt::format("{:02X}", fmt::join(head_byte, head_byte+0x10, " ")));
    this->Payload->remove(0,0x10);  //移除头部0x10字节

    Log_WXLongLinkMessage(IsRequest,SeqID,Cmd,PacketLength);
}
