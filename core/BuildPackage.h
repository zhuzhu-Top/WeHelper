//
// Created by 28264 on 2023/5/22.
//

#ifndef WEHELPER_BUILDPACKAGE_H
#define WEHELPER_BUILDPACKAGE_H

#include "../include/pub_include.h"

#include "../we_chat/WeChatBridge.h"

//#include "./WxProtobuf.h"



#pragma pack(push, 1)
struct  ClinetHello {
    uint8_t const_data[10]={
            0x00,0x00,0x00,0x9d, //包长
            0x01,
            0x04,0xf1,  //Version 可能会改变 跟现有ipad协议不一样 现在是03 f1
            0x01,  //CipherSuite个数 Maybe
            0x00,
            0xa8 //SuiteCode  AES_128_GCM_SHA256
    };
    uint8_t client_random[32] = {0x0};
    std::uint32_t timestamp=0x0;
    uint8_t const_data2[12]={
            0x00,0x00,0x00,0x6f, //包长
            0x01,
            0x00,0x00,0x00,0x6a,
            0x00,0x0f,0x01
    };
    uint8_t PSK[16*6+7] = {0x0}; //103  也有可能叫Extension
    bb::ByteBuffer GetBytes();
};
#pragma pack(pop)

#define MMTLS_Version 0xF104
#define MMTLS_Arry ()

#pragma pack(push, 1)
struct  Header {
    uint8_t plaformSign_0;//平台标识  win 00 android 0xbf
    uint8_t ziped_1;//1 压缩 2 未压缩
    uint8_t algorithm_2;////加密算法(前4bits),默认使用aes加密(5),需要rsa加密的CGI重载此虚函数
    uint8_t cookieLen_3;//cooke 长度
    uint32_t WeChatVersion_4;//微信版本
    uint32_t uin_8;// uin
    uint8_t cookie_12[15]; //cookie
    uint16_t cgi_27;  //cgi
    uint32_t pb_compress_len_29;  //压缩前长度
    uint32_t pb_compressed_len_33;  //压缩后长度
    uint16_t const_37;  //0
    uint16_t const_39;  //15
    uint8_t isCrc_41=1;    //crc 是否存在
    uint32_t crc_42;    //crc
    uint8_t const_46;        //0
    uint32_t RQT_47;
    std::string toString();
};
#pragma pack(pop)





class WeChatBridge;


class BuildPackage{

    WeChatBridge* weChatBridge = nullptr;

public:
    BuildPackage(WeChatBridge* weChatBridge);

    //构造内部包体
    void ConstructInnerPackage(bb::ByteBuffer& HeadByteBuff,std::vector<uint8_t>& pb_data,uint32_t pb_len,std::uint16_t cmdId);

    void ConstructTlsPackage(bb::ByteBuffer& HeadByteBuff,uint32_t RandomSeq,bb::ByteBuffer& OutBuff,std::uint16_t cmdID);
    uint32_t DecryptBody(struct Header& Response,uint8_t* enc_data,uint32_t remain_length,uint8_t*dec_data);
    void DeCompressBody(struct Header& Response,uint8_t* dec_data,uint32_t dec_data_len,bb::ByteBuffer& OutBuff);
    bool UnpackPackage(std::unique_ptr<bb::ByteBuffer>& out_data,struct Header& Response,bb::ByteBuffer& OutBuff,bool is_request=false);
};

void PackInnerHeader(WeChatBridge*);

#endif //WEHELPER_BUILDPACKAGE_H
