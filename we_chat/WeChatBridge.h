//
// Created by 28264 on 2023/5/26.
//

#ifndef WEHELPER_WECHATBRIDGE_H
#define WEHELPER_WECHATBRIDGE_H


#include "../include/pub_include.h"
#include "../common/ByteBuffer.hpp"


#include "../frida/core.h"



#define AES_KEY_LEN 16
#define COOKIE_LEN 15
#define LongLinkEncryptKeyLem 16
#define LongLinkEncryptIVLen 12    //

//struct AES_GCM_KEY_Struct{
//    uint8_t KEY[LongLinkEncryptKeyLem];
//    uint8_t IV[LongLinkEncryptIVLen];
//    uint8_t AAD[13];
//
//};
enum PackageType : std::uint8_t {

    AlertType=0x15,              //21
    ServerHandShakeType=0x16,  //22
    BodyType=0x17,              //23
    ClientHandShakeType=0x19, //25
};

class WeChatBridge {
private:
    Script* m_Script;
    uint32_t WeChatBaseAdd=0;


public:
    WeChatBridge();
    WeChatBridge(Script* script);

    void SetScript(Script* script){
        m_Script=script;
        dns_Initialized= false;
    }

    void InIt();


    uint32_t ReadBytes(uint64_t addr, uint32_t len, uint8_t *buff);
    uint64_t ReadPointer(uint64_t addr,bool process32= true);
    uint32_t GetModuleAdd(const char * name);
    void SocketSend(uint64_t handle,uint8_t* data,uint32_t data_len);
    void SendKeyIVSeq_ToJs();

    void LongLinkPack(bb::ByteBuffer& data,bb::ByteBuffer& out_data);
    void MMtlsEncrypt(bb::ByteBuffer& data,bb::ByteBuffer& out_data,uint32_t ClientSeq,const uint8_t* LongLinkEncryptKey,uint8_t* LongLinkEncryptIV,const uint8_t* prefix);
    void MMtlsDecrypt( bb::ByteBuffer &data,
                       uint32_t ServerSeq,
                       const uint8_t *LongLinkEncryptKey,
                       uint8_t *LongLinkEncryptIV ,bb::ByteBuffer &out_data);
    void LongLinkUnPack(bb::ByteBuffer& data,bb::ByteBuffer& out_data,bool is_from_encrypt);
    void ShortLinkUnPack(bb::ByteBuffer& data,bb::ByteBuffer& out_data,bool is_from_encrypt);

    void On_application_data_key_expansion(string data);
    void On_aes_gcm_enc(JSON& data);
    void On_aes_gcm_dec(JSON& data);
    void On_LonglinkUnpack(std::string& data,uint32_t lenght,bool is_from_encrypt=false);
    void On_ShortlinkUnpack(std::string& data,uint32_t lenght,bool is_from_encrypt=false);


    uint8_t G_AES_Key[AES_KEY_LEN];  //内层AES CBC Key
    uint8_t G_Cookie[COOKIE_LEN];
    uint8_t G_ECDH_Key[AES_KEY_LEN];
    uint32_t G_UIN;
    uint32_t isLoged;
    std::string devicesId;
    std::string wxid;


    uint8_t LongLinkEncryptKey[LongLinkEncryptKeyLem];
    uint8_t LongLinkDecryptKey[LongLinkEncryptKeyLem];
    uint8_t LongLinkEncryptIV[LongLinkEncryptIVLen];
    uint8_t LongLinkDecryptIV[LongLinkEncryptIVLen];

    string LongLinkEncryptKey_Str;
    string LongLinkDecryptKey_Str;
    string LongLinkEncryptIV_Str;
    string LongLinkDecryptIV_Str;

    uint32_t ClientSequence;

    std::atomic<bool> InnerInitlized;//AES CBC  key cookie uin 是否初始化成功


    std::vector<std::uint8_t> Unknwo_PSK;
    std::vector<std::uint8_t> PSK;
    std::vector<std::uint8_t> PskAccessKey;
    uint32_t TLS_Random_SeqId=0x60;

    std::atomic<bool> dns_Initialized;  //dns 信息是否初始化完成
    std::string dns_server_ip;
    std::string dns_authkey_str;

    std::string LonglinkHand="";
};





#endif //WEHELPER_WECHATBRIDGE_H
