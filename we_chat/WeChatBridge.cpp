//
// Created by 28264 on 2023/5/26.
//


#include "WeChatBridge.h"
#include "../core/BuildPackage.h"
#include "../core/HandleInnerPackage.h"
#include "../crypto/AES_GCM.h"
#include "../we_chat/WXLongLinkMessage.h"
#include "../core/WxProtobuf.h"
#include "../common/Utils.h"
#include "./WXCGIUrl.h"
#include <bit>

#include "../WS/WS_Main.h"
#include <WinSock2.h>

WeChatBridge::WeChatBridge(Script* script){
    this->m_Script=script;


//    string key = "56 38 6a 3a 16 67 92 2b c3 d9 d5 47 64 d4 13 4d 7e 6a 11 b8 58 46 fe ad 4b ad e7 43 59 71 3d bc 40 93 70 fd dc c3 1c 6c 55 03 c4 f7 f0 bb 41 62 92 57 d6 15 c5 01 bd 86";
//    On_application_data_key_expansion(key);
//    PackInnerHeader();


}

uint32_t WeChatBridge::ReadBytes(uint64_t addr, uint32_t len, uint8_t *buff) {
    if (addr<=0 || len<=0){
        return 0;
    }
    JSON ret=m_Script->JS_Call("ReadBytes",{
            addr,
            len
    });
    if(ret.is_array() && !ret.empty() && ret.size()>=1){
        string  ref = ret.at(0);
        return Utils::string2byte(ref,buff);
    }
    return 0;
}

uint64_t WeChatBridge::ReadPointer(uint64_t addr,bool process32) {
    uint8_t byte_buffer[64]={0};
    uint32_t byte_count= process32 ? ReadBytes(addr,4,byte_buffer) : ReadBytes(addr,4*2,byte_buffer);

    uint64_t value = 0;
    for (uint32_t i = 0; i < byte_count; ++i) {
        value |= static_cast<uint64_t>(byte_buffer[i]) << (8 * i);
    }
    return value;

}

void WeChatBridge::On_application_data_key_expansion(string str_data){
    uint8_t data[56] = {0};


    Utils::string2byte(str_data,data);

    memcpy(LongLinkEncryptKey,data,LongLinkEncryptKeyLem);                                            //0
    LongLinkEncryptKey_Str=Utils::byte2string(LongLinkEncryptKey,LongLinkEncryptKeyLem);

    memcpy(LongLinkDecryptKey,data+LongLinkEncryptKeyLem,LongLinkEncryptKeyLem);                      //16
    LongLinkDecryptKey_Str=Utils::byte2string(LongLinkDecryptKey,LongLinkEncryptKeyLem);

    memcpy(LongLinkEncryptIV, data+LongLinkEncryptKeyLem*2,LongLinkEncryptIVLen);                     //32
    LongLinkEncryptIV_Str=Utils::byte2string(LongLinkEncryptIV,LongLinkEncryptIVLen);

    memcpy(LongLinkDecryptIV, data+LongLinkEncryptKeyLem*2+LongLinkEncryptIVLen,LongLinkEncryptIVLen);//44
    LongLinkDecryptIV_Str=Utils::byte2string(LongLinkDecryptIV,LongLinkEncryptIVLen);



    LOGD(R"(
application_data_key_expansion :
            LongLinkEncryptKey : {}
            LongLinkDecryptKey : {}
            LongLinkEncryptIV  : {}
            LongLinkDecryptIV  : {}
    )",
        fmt::format("{:02X}", fmt::join(LongLinkEncryptKey, LongLinkEncryptKey+LongLinkEncryptKeyLem, " ")),
        fmt::format("{:02X}", fmt::join(LongLinkDecryptKey, LongLinkDecryptKey+LongLinkEncryptKeyLem, " ")),
        fmt::format("{:02X}", fmt::join(LongLinkEncryptIV, LongLinkEncryptIV+LongLinkEncryptIVLen, " ")),
        fmt::format("{:02X}", fmt::join(LongLinkDecryptIV, LongLinkDecryptIV+LongLinkEncryptIVLen, " ")));


    InIt();
}


void WeChatBridge::InIt() { //2FFD630


//    std::vector<uint8_t> enc_psk;
//    if(!Utils::ReadFileContent("C:\\Users\\28264\\AppData\\Roaming\\Tencent\\WeChat\\1\\psk.key",enc_psk)){
//        spdlog::error("read psk.key error");
//        return;
//    };
    std::string key_plain="Windows 10 x64";
     //fe5f2f700d1585222834b7eb4ff2cd37
    std::string md5_key=Utils::MD5(reinterpret_cast<const unsigned char *>(key_plain.c_str()), key_plain.size());

    md5_key.resize(md5_key.size()/2); //fe5f2f700d158522  只保留前面八个字节
    std::string iv(md5_key);
    iv.resize(12);//fe5f2f700d15  只保留六个字节
//std::uint8_t key[]={0x66,0x65,0x35,0x66,0x32,0x66,0x37,0x30,0x30,0x64,0x31,0x35,0x38,0x35,0x32,0x32};
//std::uint8_t iv[]={0x66,0x65,0x35,0x66,0x32,0x66,0x37,0x30,0x30,0x64,0x31,0x35};
//    Unknwo_PSK.resize(0x100);
//    AES_GCM::aes_gcm_decrypt(enc_psk.data(),enc_psk.size(),
//                             reinterpret_cast<const uint8_t *>(md5_key.c_str()),
//                             reinterpret_cast<const uint8_t *>(iv.c_str()),iv.size(),
//                             nullptr,0,
//                             nullptr,
//                             Unknwo_PSK
//                             );

    LOGD(R"(
  Unknow  PSK     : {}
  Unknow  PSK Len : {}
)", fmt::format("{:02X}", fmt::join(Unknwo_PSK.begin(), Unknwo_PSK.end(), " ")),Unknwo_PSK.size());

//    G_UIN=0xA9AAF64B;
    WeChatBaseAdd=GetModuleAdd("WeChatwin.dll");
    if (!WeChatBaseAdd){
        spdlog::error("get wechatwin.dll base address errror");
        return;
    }
    if(!ReadBytes(WeChatBaseAdd+0x2FFD424,4,(uint8_t*)&isLoged)){
        spdlog::error("get log flag error");
        return;
    }
    if (!isLoged){
        spdlog::warn("not loged");
        return;
    }
    if(ReadBytes(WeChatBaseAdd+0x2FFD440 +0x1F0,4,(uint8_t *)&G_UIN) !=4){
#ifdef LOG_LEVEL_DEBUG
        LOGD(" G_UIN : read error");
#endif
        return;
    }
    if(ReadBytes(WeChatBaseAdd+0x2FFD440 +0x428,COOKIE_LEN,G_Cookie) !=COOKIE_LEN){
#ifdef LOG_LEVEL_DEBUG
        LOGD(" G_Cookie : read error");
#endif
        return;
    }
#ifdef LOG_LEVEL_DEBUG
    bb::ByteBuffer cookie((uint8_t*)G_Cookie,COOKIE_LEN);
    LOGD(" G_Cookie : {}",cookie.getString());
#endif
    if(ReadBytes(ReadPointer(WeChatBaseAdd+0x2FFD440+0x3E0),AES_KEY_LEN,G_AES_Key) != AES_KEY_LEN){
#ifdef LOG_LEVEL_DEBUG
        LOGD(" G_AES_Key : read error");
#endif
    }
#ifdef LOG_LEVEL_DEBUG
    bb::ByteBuffer aes_cbc_key((uint8_t*)G_AES_Key,AES_KEY_LEN);
    LOGD(" G_AES_Key : {}",aes_cbc_key.getString());
    LOGD(" G_UIN : {:x}",G_UIN);
#endif
    if(ReadBytes(ReadPointer(WeChatBaseAdd+0x2FFD440+0x48C),AES_KEY_LEN,G_ECDH_Key) != AES_KEY_LEN){
#ifdef LOG_LEVEL_DEBUG
        LOGD(" G_ECDH_Key : read error");
#endif
        return;
    }
#ifdef LOG_LEVEL_DEBUG
    bb::ByteBuffer ecdh_key((uint8_t*)G_ECDH_Key,AES_KEY_LEN);
    LOGD(" G_ECDH_Key : {}",ecdh_key.getString());
#endif




    JSON ret=m_Script->JS_Call("initok",{
    });
    LOGD("WeChatBridge::initok {}",ret.dump());


    InnerInitlized=true;



}

void WeChatBridge::SocketSend(uint64_t handle, uint8_t *data, uint32_t data_len) {
    if(handle<=0 || m_Script == nullptr)
        throw "hand error";
    string str_data=Utils::byte2string(data,data_len);
    JSON ret=m_Script->JS_Call("SocketSend",{
            handle,
            str_data,
            data_len
    });
    LOGD("WeChatBridge::SocketSend {}",ret.dump());
}

void WeChatBridge::On_aes_gcm_enc(JSON& data) {
    string aes_gcm_key=data["TLS_AESGCM"]["key"];
    string plainTxt=data["TLS_AESGCM"]["plainTxt"];
    uint32_t plainTxt_len=data["TLS_AESGCM"]["plainTxt_len"];//加密之前的数据
    string aes_gcm_iv=data["TLS_AESGCM"]["iv"];
    string aes_gcm_aad=data["TLS_AESGCM"]["aad"];
    string aes_gcm_ret_data=data["TLS_AESGCM"]["ret_data"];
    uint32_t aes_gcm_ret_len=data["TLS_AESGCM"]["ret_len"];

    LOGD(R"(
[**************AES GCM 加密   Start***********]
| key:{}
| iv :{}
| aad:{}
| AES GCM 加密前数据 : 0x{:X}
| {}
| AES GCM 加密后数据 : 0x{:X}
| {}
[**************AES GCM 加密   End***********]
        )", aes_gcm_key, aes_gcm_iv, aes_gcm_aad ,plainTxt_len,plainTxt,aes_gcm_ret_len,aes_gcm_ret_data);
    uint64_t encrypt_seq= 0x0;
    {
        std::vector<uint8_t> vec_aad(13);
        Utils::string2byte(aes_gcm_aad,vec_aad.data());

        std::reverse_copy(vec_aad.data(), vec_aad.data() + sizeof(uint64_t), reinterpret_cast<uint8_t*>(&encrypt_seq));

        if(encrypt_seq<=3){
            return;
        }
        spdlog::debug("AES GCM Encrypt seq 0x{:X}",encrypt_seq);

    }
//            LongLinkEncryptKey : 94 6B C0 EB 4C F1 1A FC ED B4 2F 33 09 A2 8B FE
//            LongLinkEncryptIV  : D7 85 D3 4A 3D C2 E8 39 C7 58 70 DE

//    0x00000000 | 00 00 00 9A | 00 10 00 01 | 00 00 00 ED | 00 00 01 D7 | ................
//    0x00000010 | BF A9 5F 63 | 09 02 17 6F | 6F 63 AE 04 | 43 18 0F 00 | .._c...ooc..C...
    if (plainTxt_len>0x10 && encrypt_seq>=4){ //大于0x10  //大于等于4说明就是长连接在加密




        On_LonglinkUnpack(plainTxt,plainTxt_len,true);

        Utils::removeSpace(aes_gcm_key);
        Utils::removeSpace(aes_gcm_iv);

//        LOGD("AES GCM KEY : {}",aes_gcm_key);

        std::string real_aes_gcm_iv=aes_gcm_iv.substr(0,8);
        std::string lastEightChars = aes_gcm_iv.substr(aes_gcm_iv.size() - 16);
        //本次aes gcm 加密的 iv
        uint64_t current_last_iv_byte=Utils::stringToUint64(lastEightChars);

        uint64_t tmp_iv = current_last_iv_byte ^ encrypt_seq;//跟seq异或 得到原始iv
        tmp_iv=Utils::swapEndian(tmp_iv);
        real_aes_gcm_iv.append(Utils::byte2string((uint8_t*)&tmp_iv,sizeof(uint64_t)) );

//        LOGD("AES GCM IV : {}", real_aes_gcm_iv);

        Utils::string2byte(aes_gcm_key,LongLinkEncryptKey);
        Utils::string2byte(real_aes_gcm_iv,LongLinkEncryptIV);

        LOGD(R"(
        LongLinkEncryptKey : {}
        LongLinkEncryptIV  : {}
        )",
        fmt::format("{:02X}", fmt::join(LongLinkEncryptKey, LongLinkEncryptKey+LongLinkEncryptKeyLem, " ")),
        fmt::format("{:02X}", fmt::join(LongLinkEncryptIV, LongLinkEncryptIV+LongLinkEncryptIVLen, " ")));
        LongLinkEncryptKey_Str=aes_gcm_key;
        LongLinkEncryptIV_Str=real_aes_gcm_iv;


        ClientSequence=encrypt_seq;
        spdlog::debug("ClientSequence : {:X}",ClientSequence);

        SendKeyIVSeq_ToJs();
//  log "ReSetKeyIvReq key : d3a8a9f6b46aba42d4f9126ea5524885 iv :8dc305aca59fdd5785f8c778 req : 15"
    }

    if(aes_gcm_key!=LongLinkEncryptKey_Str){

        std::vector<std::uint32_t> vec_tls_head(4);
        Utils::string2byte(aes_gcm_ret_data.substr(0,35),(std::uint8_t*)vec_tls_head.data());

        if(vec_tls_head[1] == 0x01001000){//等于这个说明是长连接
            On_LonglinkUnpack(aes_gcm_ret_data,aes_gcm_ret_len,true);
        }else{ //否则认为是短连接
            On_ShortlinkUnpack(aes_gcm_ret_data,aes_gcm_ret_len,true);
        }
        return;
    }

    //去除空格
//    aes_gcm_key.erase(std::remove_if(aes_gcm_key.begin(), aes_gcm_key.end(), [](unsigned char c) { return std::isspace(c); }), aes_gcm_key.end());


//    std::string lastTwoChars = aes_gcm_iv.substr(aes_gcm_iv.size() - 2);
//    //本次aes gcm 加密的 iv
//    uint32_t current_last_iv_byte=Utils::stringToUint32(lastTwoChars);
//
//    ClientSequence=current_last_iv_byte ^ LongLinkEncryptIV[LongLinkEncryptIVLen-1];





}


void WeChatBridge::On_aes_gcm_dec(JSON &data) {
    string aes_gcm_key=data["TLS_AESGCM"]["key"];
    string plainTxt=data["TLS_AESGCM"]["plainTxt"];
    uint32_t plainTxt_len=data["TLS_AESGCM"]["plainTxt_len"];
    string aes_gcm_iv=data["TLS_AESGCM"]["iv"];
    string aes_gcm_aad=data["TLS_AESGCM"]["aad"];
    string aes_gcm_ret_data=data["TLS_AESGCM"]["ret_data"];
    uint32_t aes_gcm_ret_len=data["TLS_AESGCM"]["ret_len"];
    LOGD(R"(
[**************AES GCM 解密   Start***********]
| key:{}
| iv :{}
| aad:{}
| AES GCM 解密前数据 : 0x{:X}
| {}
| AES GCM 解密后数据 : 0x{:X}
| {}
[**************AES GCM 解密   End***********]
        )", aes_gcm_key, aes_gcm_iv, aes_gcm_aad ,plainTxt_len,plainTxt,aes_gcm_ret_len,aes_gcm_ret_data);
    {
        std::vector<uint8_t> vec_aad(13);
        Utils::string2byte(aes_gcm_aad,vec_aad.data());
        uint64_t decrypt_seq= 0x0;
        std::reverse_copy(vec_aad.data(), vec_aad.data() + sizeof(uint64_t), reinterpret_cast<uint8_t*>(&decrypt_seq));

        if(decrypt_seq <= 3){
            spdlog::debug("AES GCM Decrypt ShortLink Message seq 0x{:X}",decrypt_seq);

            return;
        }else{
            spdlog::debug("AES GCM Decrypt LongLink  Message seq 0x{:X}",decrypt_seq);
        }

    }

    if (plainTxt_len<0x10){ //大于0x10 取出前16字节的tls头
        return;
    }


    std::vector<std::uint32_t> vec_tls_head(4);
    Utils::string2byte(aes_gcm_ret_data.substr(0,35),(std::uint8_t*)vec_tls_head.data());


    //00 00 00 86 00 10 00 01 3b 9a ca ed

    if(vec_tls_head[1] == 0x01001000){//等于这个说明是长连接
//        uint32_t Cmd = vec_tls_head[2];
//        Cmd = Utils::swapEndian(Cmd);
//        Cmd=Cmd-1000000000;
//        if(Cgi_List.find(Cmd) == Cgi_List.end()){
//            return;
//        }
//        spdlog::info("[longlink] recv tls response {} {}",Cmd, cgi2string(Cmd));
        On_LonglinkUnpack(aes_gcm_ret_data,aes_gcm_ret_len,false);
    }else{ //否则认为是短连接
        On_ShortlinkUnpack(aes_gcm_ret_data,aes_gcm_ret_len,false);
    }



}
///
/// \param data
/// \param out_data
void WeChatBridge::LongLinkPack(bb::ByteBuffer &data, bb::ByteBuffer &out_data) {
    /*
    if (!Initialized) return;
    const uint8_t aes_gc_key[]={
            0xbb,0x8a,0x3e,0x3c,0x1f,0xc1,0x13,0xa4,0xfa,0x97,0x1f,0xcf,0x1b,0xa3,0x94,0xa3
    };
    uint8_t aes_gc_iv[]={

            0xe4,0x17,0x07,0x88,0x76,0xa8,0x2f,0xe6,0xa4,0x5f,0xb3,0x7d

    };
    WeChatBridge::ClientSequence=4;
     */
    if(ClientSequence<=0){
        spdlog::error("seq error");
        return;
    }
    spdlog::info("current ClientSequence : {} ",ClientSequence);
    static const uint8_t Prefix[]={0x17 ,0xf1 ,0x04};
    return MMtlsEncrypt(data,out_data,++ClientSequence,LongLinkEncryptKey,LongLinkEncryptIV,Prefix);
//    return MMtlsEncrypt(data,out_data,++WeChatBridge::ClientSequence,aes_gc_key,aes_gc_iv,Prefix);
}

void WeChatBridge::MMtlsDecrypt(bb::ByteBuffer &data,
                                uint32_t ServerSeq,
                                const uint8_t *LongLinkEncryptKey,
                                uint8_t *LongLinkEncryptIV,bb::ByteBuffer &out_data){

    uint8_t aes_gcm_iv[LongLinkEncryptIVLen]={0};
    memcpy(aes_gcm_iv,LongLinkEncryptIV,LongLinkEncryptIVLen);

    //IV 跟
    uint32_t iv_low32 = 0;
    memcpy(&iv_low32, &aes_gcm_iv[LongLinkEncryptIVLen - sizeof(uint32_t)], sizeof(uint32_t));
    iv_low32 = htonl(iv_low32);  //内存拷贝是小端的 需要转换
    iv_low32 ^= ServerSeq;
    iv_low32 = ntohl(iv_low32);
    memcpy(&aes_gcm_iv[LongLinkEncryptIVLen - sizeof(uint32_t)], &iv_low32, sizeof(uint32_t));


    std::vector<uint8_t> plain_txt;
    plain_txt.resize(data.size()+0x10);

    AES_GCM::aes_gcm_decrypt(data.getPtr(),data.size(),
                             LongLinkEncryptKey,
                             aes_gcm_iv, LongLinkEncryptIVLen,
//                             aes_gcm_aad, sizeof(aes_gcm_aad),
                             nullptr, 0,
                             nullptr,
                             plain_txt
                             );

    out_data.putBytes(plain_txt.data(),plain_txt.size());
}
//拼接
//3字节 {0x17 ,0xf1 ,0x04};
//2字节 包长+头部
//加密结果
//加密结果Tag
void WeChatBridge::MMtlsEncrypt(bb::ByteBuffer &data, bb::ByteBuffer &out_data,
                                uint32_t ClientSeq,
                                const uint8_t *LongLinkEncryptKey,
                                uint8_t *LongLinkEncryptIV,
                                const uint8_t *prefix

                                ) {

    bb::ByteBuffer bb_aad(0x10);
    bb_aad.putLongBE(ClientSeq);
    bb_aad.putBytes((uint8_t *)prefix,3);
    bb_aad.putShortBE(data.size()+0x10); //0x10的头

    uint8_t aes_gcm_aad[13]={0x0};
    bb_aad.getBytes(aes_gcm_aad,bb_aad.size());
//    std::cout<<bb_aad<<std::endl;
    uint8_t aes_gcm_iv[LongLinkEncryptIVLen]={0};
    memcpy(aes_gcm_iv,LongLinkEncryptIV,LongLinkEncryptIVLen);

    //IV 跟
    uint32_t iv_low32 = 0;
    memcpy(&iv_low32, &aes_gcm_iv[LongLinkEncryptIVLen - sizeof(uint32_t)], sizeof(uint32_t));
    iv_low32 = htonl(iv_low32);  //内存拷贝是小端的 需要转换
    iv_low32 ^= ClientSeq;
    iv_low32 = ntohl(iv_low32);
    memcpy(&aes_gcm_iv[LongLinkEncryptIVLen - sizeof(uint32_t)], &iv_low32, sizeof(uint32_t));

    uint8_t aes_gc_tag[]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

    uint8_t* plain_txt =new uint8_t[data.size()];

    uint32_t out_len=0;
    data.getBytes(plain_txt,data.size());
    std::unique_ptr<unsigned char[]> ciphertext = AES_GCM::aes_gcm_encrypt(
            plain_txt, data.size(),
            LongLinkEncryptKey,
            aes_gcm_iv, LongLinkEncryptIVLen,
            aes_gcm_aad, sizeof(aes_gcm_aad),
            &out_len,
            aes_gc_tag
    );
    out_data.putBytes((uint8_t *)prefix,3);
    out_data.putShortBE(data.size()+0x10); //0x10的头

    out_data.putBytes((uint8_t *)ciphertext.get(),out_len);
    out_data.putBytes(aes_gc_tag, sizeof(aes_gc_tag));
}

uint32_t WeChatBridge::GetModuleAdd(const char *name) {
    JSON ret= m_Script->JS_Call("GetModuleAdd",{name});
    if(ret.is_array() && ret.size()>0){
        return ret.at(0);
    }
    return 0;


}

WeChatBridge::WeChatBridge() {

    ClientSequence=0;



}

/// MMTls 解包 直接处理Hoo拿到TLS解密后的数据
/// \param data   Hook得到的数据
/// \param out_data  PB返回值
void WeChatBridge::LongLinkUnPack(bb::ByteBuffer &data, bb::ByteBuffer &out_data,bool is_from_encrypt) {
    //TODO  可能会直接根据recv解包 目前感觉没有必要  下面直接处理AES GCM 解密后的内容
    if(data.size()<=0){
        return;
    }

    BuildPackage buildPackage(this);
    WXLongLinkMessage Message(data);
    struct Header header;

    std::unique_ptr<bb::ByteBuffer> raw_inner_body;
//    解析0x10的头部剩下才是真正的0xbf开头的内部包
    Message.GetPayload(raw_inner_body);

    buildPackage.UnpackPackage(raw_inner_body,header,out_data,is_from_encrypt);

    if(out_data.size() ==0) return;
    ProtobufHelper helper;
    switch(header.cgi_27){
        case micromsg_bin_newsendmsg:{

            HandleInnerPackage::HandleSendMsgResponse(out_data,is_from_encrypt);

            break;
        }
        case micromsg_bin_newsync:{
//0a020800108780101af90208f30212f302082f120808011099d6f5f202120808021094def5f202120808031091d7f5f202120408041000120408051000120408061000120408071000120408081000120808091087def5f2021204080a10001208080b1089def5f2021204080d10001208080e10a8e7f4f2021208081010a8e7f4f2021208081110a8e7f4f2021206081310c485021204081410001204081510001208081610a1d3f5f2021208081710bf8dcba406120808181096e5cba4061204081a10001206081b1086bb2a1204086510001204086610001204086710001204086810001204086910001204086a10001204086b10001204086c10001204086d10001204086f10001204087010001204087210001204087a1000120908c90110f4e4cba406120908ca0110b8f2c9a406120908cb01109ec8cba406120508cc011000120508cd011000120508ce011067120508cf011000120908e8071091c3cba406120908e907108ac4cba406120908d10f108da6caa406120908d30f1092e4c6a40620022a0e57696e646f77732031302078363430033801
            JSON json_ras_msg;
            helper.parse_pb(out_data.getPtr(),out_data.size(),json_ras_msg);
            if(json_ras_msg["2"].is_string() || json_ras_msg["2"].is_number_integer() ){
                return;
            }
            std::string recy_msg_str = json_ras_msg.dump(-1,' ',false,JSON::error_handler_t::ignore);

            auto& item_2 = json_ras_msg.at("2");
            auto& item_2_2count = json_ras_msg.at("2").at("1");
            if(item_2.at("2").is_array()){//2_2 判断四不是arry
                for (auto& item_2_2: item_2.at("2") ) {
                    std::uint64_t content_type  = item_2_2.at("1");
                    switch (content_type) {
                        case 2 :{
                            std::string msg_content =item_2_2.at("2").dump(-1,' ',false,JSON::error_handler_t::ignore);

                            spdlog::info("未知内容 content : {}",msg_content);
                            break;
                        }
                        case 5 :{ //普通消息
                            auto& msg_item =  item_2_2.at("2").at("2");
                            std::string msg_from =msg_item.at("2").at("1");
                            std::string msg_to =msg_item.at("3").at("1");
                            std::string msg_content;
                            if(msg_item.at("5").is_object()){

                                msg_content=msg_item.at("5").at("1");
                            }else{
                                msg_content=msg_item.at("5");
                            };
                            spdlog::info("recv msg  from: {} msg_to {}  content : {}",msg_from,msg_to,msg_content);

                            std::string to_client_msg =msg_item.dump(-1,' ',false,JSON::error_handler_t::ignore);
                            WS_Main::SendMsg2Client(to_client_msg);
                            break;
                        }
                        case 44:{  //可能是通知关注的公众号

                            std::string msg_content =item_2_2.at("2").dump(-1,' ',false,JSON::error_handler_t::ignore);
                            spdlog::info("公众号列表:  content : {}",msg_content);

                            break;
                        }

                        default:{

                            std::string msg = json_ras_msg.dump(-1,' ',false,JSON::error_handler_t::ignore);
                            spdlog::error("反馈以下内容给开发者-> \r\n{}",msg);
                            throw "unhandle content";

//                            auto& inner_item_2_2 = item_2_2.at("2").at("2");
//
//                            std::string msg_from =  inner_item_2_2.at("2").dump(-1,' ',false,JSON::error_handler_t::ignore);
//                            std::string msg_content =inner_item_2_2.at("5").dump(-1,' ',false,JSON::error_handler_t::ignore);
//
//                            //            auto  msg_content = json_ras_msg["2"]["2"]["2"]["2"]["5"]["1"].;
//                            WS_Main::SendMsg2Client(recy_msg_str);
//                            spdlog::info("recv msg  : \r\n{}",recy_msg_str);
//
//                            //            std::string json_str;
//                            //            JSON json_body =  WxProtobuf::Parse_NewSyncResponse(out_data.getPtr(),out_data.size(),json_str);
//                            //            JSON recv_body = json_body["cmdList"]["itemList"][0]["cmdBuf"]["data"];
//
//                            //            spdlog::info("recv msg  : \r\n{}",recv_body.dump(-1,' ',false,JSON::error_handler_t::ignore));
//                            spdlog::info("default recv msg  from: {} \r\n content : {}",msg_from,msg_content);

                        }

                    }
                    
                    

                }

            }else{
                std::uint64_t content_type = item_2.at("2").at("1");
                switch (content_type) {
                    case 2 :{
//{"1":0,"2":{"1":1,"2":{"1":2,"2":{"1":919,"2":{"1":{"1":"wj1907982258wj"},"10":"","11":"","12":"","13":0,"14":0,"16":"","17":0,"18":0,"19":"Beijing","2":{"1":"鍏夌殑鍔涢噺"},"21":"涓嶇煡閬撹�翠粈涔堬紝浣嗘槸鍙堜粈涔堥兘鎯宠��","22":0,"23":1,"24":0,"26":9,"27":30,"3":{"1":"GDLL"},"30":"solodili","33":7,"34":0,"35":3,"37":{"1":1,"2":"http://shmmsns.qpic.cn/mmsns/ric3ibzib4jwutJicbjmqqyJhUFBKtWJkn3QGZ7cDPfXvgvnsfhx8Yicyu0qchYeHyFLU3nqo4X0e9jY/0","3":14134949407772250712,"4":6273,"5":4294967295},"38":"434e","39":"https://wx.qlogo.cn/mmhead/ver_1/WTmIpqavch561gO2rLqUHfnzht96WJsziaicNGNC5kIdtt0mLibP96YQUmvFG4q9GZheN8CdUnmwImDV07MRPctCRnUia3ZtASuOTkJ2KPDydag/0","4":{"1":"guangdeliliang"},"40":"https://wx.qlogo.cn/mmhead/ver_1/WTmIpqavch561gO2rLqUHfnzht96WJsziaicNGNC5kIdtt0mLibP96YQUmvFG4q9GZheN8CdUnmwImDV07MRPctCRnUia3ZtASuOTkJ2KPDydag/132","42":"0800","45":"v3_020b3826fd0301000000000051cc01de97b48d000000501ea9a3dba12f95f6b60a0536a1adb655f87616ded726c402e885ca22fb2c95e8623202994662c02f43dd522187a86fae71063dee309930547248026b@stranger","5":1,"50":{"1":"","2":0,"3":0},"53":0,"55":0,"56":0,"57":{"1":0,"3":0,"4":"","5":0,"7":0},"58":0,"6":"0800","62":"0800","64":0,"65":0,"66":0,"67":0,"7":4294967295,"70":0,"76":0,"8":8388611,"80":1,"81":{"1":0,"3":0,"4":0},"82":18446744073709551615,"83":0,"84":"0800","85":0,"86":0,"9":1}}}},"3":0,"4":{"1":371,"2":{"1":47,"2":[{"1":1,"2":777892916},{"1":101,"2":0},{"1":2,"2":777893211},{"1":102,"2":0},{"1":13,"2":0},{"1":204,"2":0},{"1":3,"2":777893212},{"1":103,"2":0},{"1":11,"2":777892929},{"1":111,"2":0},{"1":4,"2":0},{"1":104,"2":0},{"1":5,"2":0},{"1":105,"2":0},{"1":7,"2":0},{"1":107,"2":0},{"1":8,"2":0},{"1":108,"2":0},{"1":9,"2":777893121},{"1":109,"2":0},{"1":22,"2":777873825},{"1":6,"2":0},{"1":122,"2":0},{"1":106,"2":0},{"1":16,"2":777860008},{"1":17,"2":777860008},{"1":114,"2":0},{"1":14,"2":777860008},{"1":112,"2":0},{"1":19,"2":33590},{"1":26,"2":0},{"1":27,"2":712883},{"1":24,"2":1689695074},{"1":23,"2":1689676274},{"1":10,"2":0},{"1":201,"2":1689695074},{"1":205,"2":0},{"1":202,"2":1689695658},{"1":203,"2":1689673550},{"1":206,"2":103},{"1":207,"2":0},{"1":20,"2":0},{"1":21,"2":0},{"1":1000,"2":1689685201},{"1":1001,"2":1689685322},{"1":2001,"2":1689660307},{"1":2003,"2":1689689107}]}},"5":1,"6":539181663,"7":1689695689,"8":{"1":17,"2":{"1":{"1":[2,26,27],"2":3342101864,"3":1001}}}}
                        std::string msg_content = json_ras_msg.at("2").at("2").at("2").at("2").dump(-1,' ',false,JSON::error_handler_t::ignore);
                        spdlog::info("未知内容 content : {}",msg_content);
                        break;
                    }
                    case 5 :{

                        auto& item_2_2_2_2 = json_ras_msg.at("2").at("2").at("2").at("2");
                        std::string msg_from =  item_2_2_2_2.at("2").dump(-1,' ',false,JSON::error_handler_t::ignore);
                        std::string msg_content =item_2_2_2_2.at("5").dump(-1,' ',false,JSON::error_handler_t::ignore);
                        spdlog::info("recv msg  from: {} \r\n content : {}",msg_from,msg_content);
                        std::string to_client_msg  = item_2_2_2_2.dump(-1,' ',false,JSON::error_handler_t::ignore);
                        WS_Main::SendMsg2Client(to_client_msg);
                        break;
                    }
                    default : {

                        std::string msg = json_ras_msg.dump(-1,' ',false,JSON::error_handler_t::ignore);
                        spdlog::error("反馈以下内容给开发者-> \r\n{}",msg);
                        throw "unhandle content";
                    }

                }
                

            }

            break;
        }
        case micromsg_bin_heartbeat:{
            spdlog::info("recv heart beat");
            break;
        }

        default:{
            spdlog::info(R"("
[longLink] unhandle cgi {}
[longLink] unhandle data {}
")",header.cgi_27,out_data.getString());


        }


    }
}
///
/// \param data  原始包
/// \param out_data 返回解析的PB
/// \param is_from_encrypt  是否来着发送包
void WeChatBridge::ShortLinkUnPack(
        bb::ByteBuffer &data,
        bb::ByteBuffer &out_data,
        bool is_from_encrypt
        ) {
    if(data.size()<=0){
        return;
    }

    BuildPackage buildPackage(this);
    struct Header header;

    std::unique_ptr<bb::ByteBuffer> raw_inner_body = std::make_unique<bb::ByteBuffer>(data);

    buildPackage.UnpackPackage(raw_inner_body,header,out_data,is_from_encrypt);

    if(out_data.size() ==0) return;

    switch (header.cgi_27) {

        case micromsg_bin_getcdndns: {
            HandleInnerPackage::HandleGetCDNDns(out_data);

            break;
        }
        case micromsg_bin_statusnotify : {
            //0a040800120010cfeee0cf0618df8cbae996a8beea09201e2a150a13777869645f347a7236313669723666693132322a110a0f67685f3232666233336636376337652a110a0f67685f6430373338353738323863662a110a0f67685f3863343237633832666132342a110a0f67685f3630393564386439303134362a110a0f67685f3237313633336234663537372a110a0f67685f6530613035393839393335362a110a0f67685f3366633163656362366635302a110a0f67685f3439333539373038663636392a0c0a0a66696c6568656c7065722a110a0f67685f6236653365323762356463632a110a0f67685f6366373132633831333563362a110a0f67685f3838366239343837323239342a110a0f67685f3461356439653462623466662a110a0f67685f6634353830633031303639632a110a0f67685f3834326539383530376465342a110a0f67685f3132633735373964366633372a110a0f67685f3032336163626331316336362a110a0f67685f3231363564373564643533382a110a0f67685f3938616137353839623635302a110a0f67685f6135653939616535306462332a110a0f67685f3730616634386134383165312a110a0f67685f6636343239316336666365662a110a0f67685f6564313565383866366638372a110a0f67685f3934303434653432313761622a110a0f67685f3037326339393335333161642a110a0f67685f6332303236663138323064362a110a0f67685f6537653731666539326331392a110a0f67685f3631366662306664343832362a110a0f67685f633462336535363838333265
//            里面有关注的公众号 好友 暂不处理
            break;
        }
        case micromsg_bin_uploadmsgimg :{
            //0a040800120010ccdef5f2021a220a20643634623739333439623336323336386533326533386233336632333864643322150a13777869645f6c6b72727a6f6b633765706e32322a150a13777869645f347a72363136697236666931323230ab2238ab2240004800509884bec8a29cdfcc1d5a20323831356662616238356535616361333165373136643663386164366130316362b201333035373032303130303034346233303439303230313030303230346637343733666539303230333266353333663032303462343830333336663032303436343933306236383034323433393635363233303635333336353333326433383332363633303264333436323636333032643338363333363331326436343330363633343334363433393336333433353633333130323034303131343138303230323031303030343035303034633464666630306a6b3c6d7367736f757263653e0a093c7365635f6d73675f6e6f64653e0a09093c757569643e63303730333862373735396165386231653136623338363333393163663638345f3c2f757569643e0a093c2f7365635f6d73675f6e6f64653e0a3c2f6d7367736f757263653e0a7000
            spdlog::info("uploadmsgimg -> {}",out_data.getString());
            break;
        }
        default:{
            spdlog::info(R"("
[shortLink] unhandle cgi {}
[shortLink] unhandle data {}
")",header.cgi_27,out_data.getString());


        }
    }


}


void WeChatBridge::On_LonglinkUnpack(std::string& in_data, uint32_t lenght,bool is_from_encrypt) {


    bb::ByteBuffer data;
    bb::ByteBuffer out_data;
//    uint8_t byte_data [] ={0x00,0x00,0x00,0x14,0x00,0x10,0x00,0x01,0x00,0x00,0x00,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02};
//    uint8_t aes_key [] = {0x40,0x6b,0x3b,0x33,0x6c,0x47,0x73,0x41,0x6c,0x76,0x32,0x23,0x6e,0x38,0x29,0x31};

//    memcpy(this->G_AES_Key,aes_key, sizeof(aes_key));
    if(!InnerInitlized){
        InIt();
        if(!InnerInitlized){
            return;
        }
    }
    uint8_t * byte_data=new uint8_t[lenght*2+1];
    Utils::string2byte(in_data,byte_data);
    data.putBytes(byte_data, lenght);


    LongLinkUnPack(data,out_data,is_from_encrypt);
//    if(out_data.size() != 0){
//        static ProtobufHelper protobufHelper;
//        uint32_t pb_lenght=out_data.size();
//        memset(byte_data,0x0,lenght*2+1);
//        out_data.getBytes(byte_data,pb_lenght);
//        JSON js_data;
//
//        if( protobufHelper.parse_pb(byte_data,pb_lenght,js_data)){
//            auto json_dump= js_data.dump(-1,' ',false,JSON::error_handler_t::ignore);
//            WS_Main::SendMsg2Client(json_dump);
////            wsServer->SendMsg2Client(json_dump);
//            spdlog::info("{} longlink unpack -> {}",is_from_encrypt ? "[request]" : "[response]",json_dump);
//        }else{
//            LOGD("长连接解包 原始PB : {}",spdlog::to_hex(byte_data,byte_data+pb_lenght,32));
//
//        }
//
//    }else{


    delete[] byte_data;
//    std::cout<<out_data<<std::endl;

}

void
WeChatBridge::On_ShortlinkUnpack(
        string &in_data,
        uint32_t lenght,
        bool is_from_encrypt) {
    if(!InnerInitlized){
        InIt();
        if(!InnerInitlized){
            spdlog::error("init inner decrypt info error");
            return;
        }
    }
    bb::ByteBuffer data;
    bb::ByteBuffer out_data;
    uint8_t * byte_data=new uint8_t[lenght*2+1];
    Utils::string2byte(in_data,byte_data);
    data.putBytes(byte_data, lenght);


    ShortLinkUnPack(data,out_data,is_from_encrypt);

}
/// 发送 key iv seq 到js ,js才可以保证这边的seq能一直使用
void
WeChatBridge::SendKeyIVSeq_ToJs() {
    if(m_Script == nullptr)
        throw "m_Script error";

//    string LongLinkEncryptKey_Str;
    std::uint32_t  tmp_seq = ClientSequence+1;

    std::uint8_t tmp_4 =  LongLinkEncryptIV[LongLinkEncryptIVLen-1];
    std::uint8_t tmp_3 =  LongLinkEncryptIV[LongLinkEncryptIVLen-2];
    std::uint8_t tmp_2 =  LongLinkEncryptIV[LongLinkEncryptIVLen-3];
    std::uint8_t tmp_1 =  LongLinkEncryptIV[LongLinkEncryptIVLen-4];
    std::uint32_t iv_low32 =
                (tmp_1 & 0xFFFFFFFF) <<24  |
                (tmp_2 & 0xFFFFFFFF) <<16  |
                (tmp_3 & 0xFFFFFFFF) <<8   |
                (tmp_4 & 0xFFFFFFFF) <<0;
    iv_low32 ^= tmp_seq;

    std::vector<std::uint8_t> tmp_iv;
    tmp_iv.resize(LongLinkEncryptIVLen);
    memcpy(tmp_iv.data(),LongLinkEncryptIV,LongLinkEncryptIVLen);

    (*((std::uint32_t*)tmp_iv.data()+2)) = Utils::swapEndian(iv_low32);

    std::string tmp_iv_str = Utils::byte2string(tmp_iv.data(),tmp_iv.size());


    std::uint64_t tmp_aad  = Utils::swapEndian((std::uint64_t)tmp_seq);
    std::string aad_str =  Utils::byte2string((std::uint8_t *)&tmp_aad,sizeof(std::uint64_t));

    JSON ret=m_Script->JS_Call("resetkeyivreq",{
            LongLinkEncryptKey_Str,
            tmp_iv_str,
            aad_str
    });
    LOGD("WeChatBridge::SendKeyIVSeq_ToJs {}",ret.dump());


//log "recv key : aff1ee4d95ace466601e24c8d57efbfb iv :6fbac6de687ebd829fbace60 req : 74"
}




