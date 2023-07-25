//
// Created by 28264 on 2023/7/11.
//

#include "HVSocket.h"
#include "../crypto/CryptoTools.h"
#include "../common/ByteBuffer.hpp"
#include "../common/Utils.h"
#include "../we_chat/CDNPack.h"
#include "spdlog/spdlog.h"


HVsocket::HVsocket(int port,std::string host,std::function<void(HVsocket* hvSocket,const std::uint8_t*,std::uint32_t)> callBack) : onMessageCallBack(callBack){
    real_content.reserve(0x10000);
    int _fd =client.createsocket(port,host.c_str());
    if (_fd < 0) {
        connected= false;
        return;
    }
    client.onConnection = std::bind(&HVsocket::OnConnected,this,std::placeholders::_1);
    client.onMessage = std::bind(&HVsocket::onMessage,this,std::placeholders::_1,std::placeholders::_2);
    client.start();
}
std::string
HVsocket::StartDownload(std::uint32_t UIN,std::string& aes_key_str,std::string& fileid,std::string& authkey_str) {
    while (connected==
           false);

    CDNPack cdnPack;
//    std::uint8_t aes_key[] =  {0x5a,0x2c,0xa4,0xe2,0xdd,0x87,0x3a,0x85,0xd7,0xc4,0xa3,0xc6,0xef,0xf1,0x82,0xab};
//    std::string aes_key_str;
//    std::string fileid = "3057020100044b30490201000204c33e1a1b02032f501e02046b845ad3020464b13a0c042432333033663564652d393239642d346335382d626462392d326339613264363261623930020401150a020201000405004c54a200";
//    std::string authkey_str;
//    std::uint8_t authkey[] =  {0x30,0x3e,0x02,0x01,0x01,0x04,0x37,0x30,0x35,0x02,0x01,0x01,0x02,0x01,0x01,0x02,
//                               0x04,0x6f,0x6f,0x63,0xae,0x02,0x01,0x00,0x02,0x01,0x00,0x02,0x04,0x8f,0x87,0x13,
//                               0x70,0x02,0x03,0x2f,0x77,0xf7,0x02,0x04,0x9b,0xe1,0x2e,0x70,0x02,0x04,0x9d,0xe1,
//                               0x2e,0x70,0x02,0x04,0x65,0x00,0x4d,0x81,0x02,0x04,0x83,0xc7,0x4a,0xa8,0x04,0x00
//                             };
//    aes_key_str.resize(sizeof(aes_key));
//    authkey_str.resize(sizeof(authkey));
//    std::memcpy((std::uint8_t*)aes_key_str.data(),aes_key,sizeof(aes_key));
//    std::memcpy((std::uint8_t*)authkey_str.data(),authkey,sizeof(authkey));

    bb::ByteBuffer askReadPack =  cdnPack.AskCdnReadyPack(UIN,authkey_str);

    //询问资源是否准备完成
    client.send(askReadPack.getPtr(),askReadPack.size());

    auto future =  askReadyPromise.get_future();
    if(future.wait_for(std::chrono::seconds(10))!=std::future_status::ready){
        spdlog::error("download  ask read error");
        throw "error";
    }
    if(askReadyResponse["retcode"]!="0"){
        spdlog::error("download img ask read error");
        throw "error";
    }
    bb::ByteBuffer realRequestPack =  cdnPack.RealCdnRequestPack(UIN,aes_key_str,authkey_str,fileid);
//    auto tmp_str =realRequestPack.getString();

    //发送获取真正内容的请求
    client.send(realRequestPack.getPtr(),realRequestPack.size());
    future =  real_request_promise.get_future();
    if(future.wait_for(std::chrono::seconds(20))!=std::future_status::ready){
        spdlog::error("download img ask readl request error");
        throw "error";
    }
    std::string totalsize_str =  real_response.at("totalsize");
    totalsize=std::atol(totalsize_str.c_str());

    auto recv_compete_future =  real_request_recv_complete_promise.get_future();
    if(recv_compete_future.wait_for(std::chrono::seconds(100))!=std::future_status::ready){
        spdlog::error("donwload img content time out");
        throw "error";
    }
    recv_compete_future.get();//等待接受包体完成
//    std::string tmp_str = real_content.getString();

    client.closesocket();

    std::string plain_body;
    plain_body.resize(real_content.size());
    std::uint32_t plain_body_len = CryptoTools::Dec_AES_ECB(real_content.getPtr(),
                                                            real_content.size(),
                                                            (std::uint8_t*)aes_key_str.data(),
                                                            (std::uint8_t*)plain_body.data());
    plain_body.resize(plain_body_len);

    return std::move(Utils::base64_encode(plain_body));
//    auto second_package_future = sencond_package_promise.get_future();
//    if(second_package_future.wait_for(std::chrono::seconds(1000))!=std::future_status::ready){
//        spdlog::error("donwload secdond package time out");
//        return;
//    }
}
void
HVsocket::OnConnected(const hv::SocketChannelPtr& channel) {

    std::string peeraddr = channel->peeraddr();
    if (channel->isConnected()) {
        connected= true;
        printf("connected to %s! connfd=%d\n", peeraddr.c_str(), channel->fd());

    }else {
        disconnected= true;
        printf("disconnected to %s! connfd=%d\n", peeraddr.c_str(), channel->fd());
    }
}
void
HVsocket::onMessage(
        const hv::SocketChannelPtr &channel,
        hv::Buffer *buf) {
    std::uint8_t * data = (std::uint8_t*)buf->data();
    std::uint32_t data_size = buf->size();
    spdlog::info("socket recv len : {}",data_size);
//    if(start_unkonw_header){
//
//        return ;
//    }
    if(start_recv_body){ //接受服务器发送的真正的包 图片的具体内容  //开始接受第一个包的具体内容
        real_content.putBytes((std::uint8_t*)data,data_size);
        if(real_content.size()>=totalsize){
//            spdlog::info("package body {}",real_content.getString());
            spdlog::info("recv body complete ,total size {}",real_content.size());
            realContentComplete= true;
//            start_unkonw_header=true;
            start_recv_body= false;
            real_request_recv_complete_promise.set_value( true);

        }
        return ;
    }
    std::uint32_t handed_bytes = 0 ;
    while (data_size>handed_bytes){  //实际包长大于 协议里面的包长说明有多个包组合在里面了
        bb::ByteBuffer tmp_buffer;
        tmp_buffer.putBytes((std::uint8_t*)data,0x5); //先拿出AB和包总长
        if(buf->size()<5){ //CDN 收到未知结果
            throw "error";
        }
        if((std::uint8_t)tmp_buffer.getChar() != 0xAB){
            throw "error";
        }


        std::uint32_t  currnt_package_size = tmp_buffer.getIntBE();
        std::map<std::string,std::string> map_value;

        if(currnt_package_size>data_size){  //如果当前包大于实际读取的包长，说明这个包就是包体，只是内容太长被截断了
            tmp_buffer.putBytes((std::uint8_t*)data+handed_bytes+0x5,data_size-handed_bytes-0x5);
        }else{
            tmp_buffer.putBytes((std::uint8_t*)data+handed_bytes+0x5,currnt_package_size-handed_bytes-0x5); //拿出当前包的具体内容
        }




        std::uint16_t flag = tmp_buffer.getShortBE();
        tmp_buffer.getInt();                                //版本号返回为0 不关注
        tmp_buffer.setReadPos(tmp_buffer.getReadPos()+10); //不关注10个0


        std::uint32_t innerBodyLen  = tmp_buffer.getIntBE();

        handed_bytes+=
                +5
                +2   //flag
                +0x4 //version
                +10 //zero
                +4;
        while (tmp_buffer.size()>tmp_buffer.getReadPos()){
            std::uint32_t key_name_len =tmp_buffer.getIntBE();

            std::string key;
            key.resize(key_name_len);
            tmp_buffer.getBytes((std::uint8_t *)key.data(),key.size());

            std::uint32_t value_len =tmp_buffer.getIntBE();

            std::string value;
            value.resize(value_len);
            tmp_buffer.getBytes((std::uint8_t *)value.data(),value.size());

            map_value[std::move(key)]=std::move(value);

            handed_bytes+= 0x4 +key_name_len + 4 + value_len;

        }

        switch (flag) {
            case 0x2AFC:{
                if(!askReadyComplete){            //处理ask read response
                    askReadyComplete= true;
                    askReadyResponse=map_value;
                    askReadyPromise.set_value(true);
                    break;
                }
                if(map_value["retcode"] =="0"){
                    spdlog::error("download recv real content sucess  ");
                    return;
                }
//            hvSocket->promise->set_value(map_value);
                break;
            };
            case 0x5208:{
                if(!realContentComplete){
                    //处理服务端发送的关于资源的具体信息  图片的长度
                    real_response=map_value;
                    start_recv_body=true;
                    real_request_promise.set_value(
                            true);
                }
                break;
            }
        }

    }


//    onMessageCallBack(this,data,buf->size());
//    printf("onMessage< %.*s\n", (int)buf->size(), (char*)buf->data());
}
void
HVsocket::onWriteComplete(
        const hv::SocketChannelPtr &channel,
        hv::Buffer *buf) {

    std::uint8_t * data_addr = static_cast<uint8_t *>(buf->data());

    printf("onWriteComplete > %.*s\n", (int)buf->size(), (char*)buf->data());
}










