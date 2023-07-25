//
// Created by 28264 on 2023/6/23.
//

#include "WXShortLinkMessage.h"

#include "../common/Utils.h"

#include "../core/BuildPackage.h"
#include <libhv/include/hv/requests.h>

WXShortLinkMessage::WXShortLinkMessage(
        std::string host,
        std::string cgiurl,
        bb::ByteBuffer& data) {
    tlsInnerBody.putIntBE(
             host.size()+2
             +cgiurl.size()+2
             +data.size()+4
             );

    tlsInnerBody.putShortBE(cgiurl.size());  //CGI
    tlsInnerBody.putBytes((uint8_t*)cgiurl.c_str(),cgiurl.size());

    tlsInnerBody.putShortBE(host.size()); //HOST
    tlsInnerBody.putBytes((uint8_t*)host.c_str(),host.size());

    tlsInnerBody.putIntBE(data.size()); //Data
    tlsInnerBody.put(&data);


}

void
WXShortLinkMessage::ShortLinkPack() {
    if(weChatBridge==
       nullptr){
        throw "error";
    }

    static uint8_t Prefix[]={0x0 ,0xf1 ,0x04};


//    bb::ByteBuffer result;

    // ClientHelloItem
    bb::ByteBuffer bb_ClientHello;  //packet1
    std::uint32_t ticket = CreateClientHello(bb_ClientHello);

    std::vector<std::uint8_t> clinetHello_sha256(0x20);
    Utils::sha256(bb_ClientHello.getPtr(),bb_ClientHello.size(),clinetHello_sha256);

    static std::string hkdf_label="early data key expansion";
    bb::ByteBuffer hkdf_info;
    hkdf_info.putBytes((std::uint8_t*)hkdf_label.c_str(),hkdf_label.size()); //放入labal
    hkdf_info.putBytes(clinetHello_sha256.data(),clinetHello_sha256.size());//放入packge1的sha256


    std::vector<std::uint8_t> hkdfret = Utils::HKDF(weChatBridge->PskAccessKey,hkdf_info.getRef(),28);

    std::uint8_t encrypt_key[16]={0};
    std::uint8_t encrypt_iv[28-16]={0};//12

    memcpy(encrypt_key,hkdfret.data(),sizeof(encrypt_key));
    memcpy(encrypt_iv,hkdfret.data()+sizeof(encrypt_key),sizeof(encrypt_iv));

    Prefix[0]=PackageType::ClientHandShakeType;
    sendPackage.putBytes( Prefix,sizeof(Prefix));//0x19, 0xf1, 0x04
    sendPackage.putShortBE(bb_ClientHello.size());//19 f1 04   //内部包长 00 a1
    sendPackage.put(&bb_ClientHello);

    hash_data.put(&bb_ClientHello);



    bb::ByteBuffer bb_client_handshake;  //packet2 第二个包
    /*
     * 00 00 00 10
       08
       00 00 00 0b
          01
          00 00 00 06
             00 12
             64 95 c1 af  ticket
     * */
    static const std::uint8_t const_package2[]={0x00,0x00,0x00,0x10,0x08,0x00,0x00,0x00,0x0b,0x01,0x00,0x00,0x00,0x06,0x00,0x12};
    bb_client_handshake.putBytes((std::uint8_t*)&const_package2,sizeof(const_package2));
    bb_client_handshake.putIntBE(ticket);//必须跟第一个包一样  测试观察的
    bb::ByteBuffer enc_client_handshake;
    Prefix[0]=PackageType::ClientHandShakeType;  //0x19, 0xf1, 0x04
    weChatBridge->MMtlsEncrypt(bb_client_handshake,enc_client_handshake,1,encrypt_key,encrypt_iv,Prefix);

    sendPackage.put(&enc_client_handshake);

    hash_data.put(&bb_client_handshake);

    bb::ByteBuffer enc_body_data;  //packet3
    Prefix[0]=PackageType::BodyType;  //0x17, 0xf1, 0x04
    weChatBridge->MMtlsEncrypt(tlsInnerBody,          enc_body_data,       2,encrypt_key,encrypt_iv,Prefix);
    sendPackage.put(&enc_body_data);


    static const std::uint8_t package4[]={ 0x00, 0x01, 0x01};
    bb::ByteBuffer bb_packet4;  //packet4
    bb_packet4.putIntBE(sizeof(package4));
    bb_packet4.putBytes((std::uint8_t*)&package4,sizeof(package4));

    bb::ByteBuffer enc_packet4;
    Prefix[0]=PackageType::AlertType;  //0x15, 0xf1, 0x04
    weChatBridge->MMtlsEncrypt(bb_packet4,enc_packet4,                  3,encrypt_key,encrypt_iv,Prefix);
    sendPackage.put(&enc_packet4);




}

std::uint32_t WXShortLinkMessage::CreateClientHello(
        bb::ByteBuffer &bb_ClientHello) {

    ClinetHello clinetHello;
//    std::uint32_t ticket=0x649c36a3 ;
    std::uint32_t ticket=Utils::getULongTimeStmp();

//    std::uint8_t random[]={
//            0x24,0x64,0xc7,0x44,0xb0,0xdc,0x59,0xd8,0xdd,0xe9,0xed,0x29,0xe8,0xfb,0x23,0x68,
//            0x63,0xc1,0x9e,0x3f,0xd3,0x99,0x8b,0xa9,0x21,0x1e,0xb7,0xf1,0x40,0x6c,0x0c,0xe8
//    };
//memcpy(clinetHello.client_random,random,sizeof(random));
    auto random_bytes =  Utils::generateRandomBytes(32);
    memcpy(clinetHello.client_random,random_bytes.data(),random_bytes.size());

//    clinetHello.timestamp=Utils::getULongTimeStmp();

//    std::uint8_t PSK[]={0x00,0x00,0x00,0x63,0x01,0x00,0x09,0x3a,0x80,0x00,0x00,0x00,0x00,0x00,0x48,0x00,
//                        0x0c,0x9a,0x9b,0x6e,0xf8,0x6a,0xe8,0xcf,0x05,0x29,0x2d,0xdf,0x1f,0x00,0x48,0x4e,
//                        0x67,0x35,0x80,0x19,0xd1,0xc1,0x29,0x26,0xd6,0xc6,0xbf,0xc0,0x8f,0x0e,0x43,0xfa,
//                        0x59,0xed,0x49,0xcb,0xf6,0x55,0x31,0x69,0x67,0x43,0x5d,0x00,0x4f,0xf2,0x42,0xed,
//                        0x3b,0x61,0xd2,0x52,0x72,0x86,0x4e,0x6c,0x55,0x66,0x3a,0xb6,0x03,0x1e,0xe7,0x84,
//                        0x89,0x32,0x99,0x7f,0xb0,0xd6,0x87,0xcb,0x7e,0x7b,0x7b,0x9a,0x24,0x54,0x86,0x5b,
//                        0xaa,0xf1,0x2d,0x89,0x62,0x3f,0xe2};
    clinetHello.timestamp=Utils::swapEndian(ticket);
    memcpy(clinetHello.PSK,weChatBridge->PSK.data(),weChatBridge->PSK.size());
//58
    bb_ClientHello =clinetHello.GetBytes();

    return ticket;
}

bb::ByteBuffer
WXShortLinkMessage::Post() {

    std::string url = "http://szextshort.weixin.qq.com/mmtls/"+std::to_string(Utils::getULongTimeStmp());
//    std::string url = "http://112.53.55.70/mmtls/"+std::to_string(Utils::getULongTimeStmp());


    std::string reqBody ;
    reqBody.resize(sendPackage.size());
    memcpy((void*)reqBody.c_str(),sendPackage.getPtr(),sendPackage.size());

    auto response =  requests::post(url.c_str(),reqBody);

    if(response->status_code ==http_status::HTTP_STATUS_OK ){
        resp_body.putBytes((uint8_t*)response->Body().c_str(),response->Body().size());
        return std::move(ShortLinkUnPack());
    }else{
        throw "error";
    }


}

bb::ByteBuffer
WXShortLinkMessage::ShortLinkUnPack() {

    Parse();

    hash_data.put(&(*vec_packages.begin()));

    std::vector<std::uint8_t> serverHello_sha256(0x20);
    Utils::sha256(hash_data.getPtr(),hash_data.size(),serverHello_sha256);

    static std::string hkdf_label="handshake key expansion";
    bb::ByteBuffer hkdf_info;
    hkdf_info.putBytes((std::uint8_t*)hkdf_label.c_str(),hkdf_label.size()); //放入labal
    hkdf_info.putBytes(serverHello_sha256.data(),serverHello_sha256.size());//放入packge1的sha256


    std::vector<std::uint8_t> hkdfret = Utils::HKDF(weChatBridge->PskAccessKey,hkdf_info.getRef(),28);

    std::uint8_t encrypt_key[16]={0};
    std::uint8_t encrypt_iv[28-16]={0};//12

    memcpy(encrypt_key,hkdfret.data(),sizeof(encrypt_key));
    memcpy(encrypt_iv,hkdfret.data()+sizeof(encrypt_key),sizeof(encrypt_iv));

    bb::ByteBuffer server_handshake;
    weChatBridge->MMtlsDecrypt(vec_packages[1],1,encrypt_key,encrypt_iv,server_handshake);

    bb::ByteBuffer body_package;
    weChatBridge->MMtlsDecrypt(vec_packages[2],2,encrypt_key,encrypt_iv,body_package);

//    bb::ByteBuffer package4;
//    weChatBridge->MMtlsDecrypt(vec_packages[3],3,encrypt_key,encrypt_iv,package4);

    return std::move(body_package);
}

void
WXShortLinkMessage::Parse() {
//    static uint8_t Prefix[]={0x0 ,0xf1 ,0x04};


    std::uint8_t packageType = resp_body.getChar();
    std::uint16_t packageVersion = resp_body.getShort();
    packageVersion=Utils::swapEndian(packageVersion);
    while (packageVersion==MMTLS_Version){
        std::uint16_t packafe_lenght = resp_body.getShortBE();

        bb::ByteBuffer package_body;
        package_body.resize(packafe_lenght);
        resp_body.getBytes(package_body.getPtr(),packafe_lenght);
        vec_packages.push_back(std::move(package_body));



        packageType = resp_body.getChar();
        packageVersion = resp_body.getShortBE();

    }





}
