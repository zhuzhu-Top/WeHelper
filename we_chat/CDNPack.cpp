//
// Created by 28264 on 2023/7/13.
//

#include "CDNPack.h"

#include "../common/Utils.h"
#include "../crypto/CryptoTools.h"

static std::string clientversion = "1661534743";

bb::ByteBuffer
CDNPack::AskCdnReadyPack(
        std::uint32_t UIN,
        std::string &authkey) {

    bb::ByteBuffer buffer(0x200);
    std::vector<MapTyep> ascReadyPackage= {
            {"ver",           "1"},
            {"weixinnum",     std::to_string(UIN)},//1869570990
            {"province",      "16"},
            {"city",          "19"},
            {"isp",           "3"},
            {"rulekey",       "1_0_0_0_-1"},
            {"expectrulekey", "1_1_2_2_-1"},
            {"seq",           std::to_string(++seq)},
            {"clientversion", clientversion},
            {"clientostype",  "Windows 10 x64"},
            {"authkey",  authkey},
            {"nettype",  "1"},
            {"acceptdupack",  "1"},
    };
    std::uint16_t flag =0x2714;
    return std::move(PackHeader(ascReadyPackage,UIN,flag));
}

bb::ByteBuffer
CDNPack::PackHeader(
        std::vector<MapTyep>& innerPackage,
        std::uint32_t UIN,
        std::uint16_t flag) {
    bb::ByteBuffer innerBody(0x200);
    for (auto item : innerPackage) {
        std::string key =item.key;
        std::string value =item.value;

        innerBody.putIntBE(key.size());
        innerBody.putBytes((std::uint8_t*)key.data(),key.size());
        innerBody.putIntBE(value.size());
        innerBody.putBytes((std::uint8_t*)value.data(),value.size());
    }

    bb::ByteBuffer body(0x200);

    body.putChar(0xAB);
    body.putIntBE(25+innerBody.size());  //20是头部字节个数 这里是全包总长

//    body.putChar(0x27);//flag
//    body.putChar(0x14);
    body.putShortBE(flag);
    body.putInt(UIN);

    std::uint8_t const_zero[] = {00 ,00 ,00 ,00 ,00,     00 ,00 ,00,00,0x00 };
    body.putBytes((std::uint8_t*)&const_zero,sizeof(const_zero));
    body.putIntBE(innerBody.size());  //剩下 的包长
    body.put(&innerBody);

    std::string tmp_str = body.getString();
    return std::move(body);
}

bb::ByteBuffer
CDNPack::RealCdnRequestPack(
        std::uint32_t UIN,
        std::string& aes_key,
        string &authkey,
        string &fileid
        ) {
    bb::ByteBuffer body(0x200);

    auto vec_find_func = [](std::vector<MapTyep>& vec,std::string key){
        auto result = std::find_if(
                std::begin(vec),
                std::end(vec),[&key](const MapTyep& item){
                    return item.key==key;
                });
        return std::move(result);
    };

    vec_find_func(requestItem,"weixinnum")->value=std::to_string(UIN);
    vec_find_func(requestItem,"seq")->value=std::to_string(++seq);
    vec_find_func(requestItem,"authkey")->value=authkey;
    vec_find_func(requestItem,"taskid")->value=std::to_string(++taskid);
    vec_find_func(requestItem,"fileid")->value=fileid;
    {
        std::string rsa_n = "BFEDFFB5EA28509F9C89ED83FA7FDDA8881435D444E984D53A98AD8E9410F1145EDD537890E10456190B22E6E5006455EFC6C12E41FDA985F3"
                            "8FBBC7213ECB810E3053D4B8D74FFBC70B4600ABD728202322AFCE1406046631261BD5EE3D44721082FEAB74340D73645DC0D02A293B962B9D"
                            "47E4A64100BD7524DE00D9D3B5C1";

        bb::ByteBuffer bb_aes_key;
        bb_aes_key.putBytes((std::uint8_t*)aes_key.data(),aes_key.size());
        bb::ByteBuffer enc_aes_key = CryptoTools::RSA_Pub_Enc(bb_aes_key,rsa_n);

        std::string enc_ase_key_str;
        enc_ase_key_str.resize(enc_aes_key.size());
        std::memcpy((std::uint8_t*)enc_ase_key_str.data(),enc_aes_key.getPtr(),enc_aes_key.size());
        vec_find_func(requestItem,"rsavalue")->value=enc_ase_key_str;
    }

    std::uint16_t flag=0x4E20;
    return std::move(PackHeader(requestItem,UIN,flag));
}
