//
// Created by 28264 on 2023/6/12.
//

#include "WS_Server.h"
#include "../include/pub_include.h"
#include "../common/Utils.h"
#include "../include/SimpleIni.h"
//
#include <nlohmann/json.hpp>

extern class WeChatBridge* weChatBridge;

using JSON = nlohmann::json;

extern class WeChatBridge* weChatBridge;
class WsBridge wsBridge;


class WS_Context{

public:
    void Init(std::string UUID,WebSocketChannelPtr webSocketChannelPtr){

    }

    std::string UUID;
    WebSocketChannelPtr webSocketChannelPtr;
};


WS_Server::WS_Server() {
    CSimpleIniA ini;

    ini.SetUnicode();

    SI_Error rc = ini.LoadFile(DEFAULT_ConfigFileNmae.c_str());
    if (rc < 0) {
        spdlog::info("not set config file ;  use default config");

        return;
    };
    std::string server_port_str = ini.GetValue("basic", "server_port", "8080");
    DEFAULT_PORT = std::stoi(server_port_str.c_str());

    ini.SaveFile(DEFAULT_ConfigFileNmae.c_str());
//    DEFAULT_PORT
}


void WS_Server::run() {
    wsBridge.set_WeChatBridge(weChatBridge);


//    http.Static("/", "./html");
    http.GET("/ping", [](const HttpContextPtr& ctx) {

        return ctx->send("pong");
    });
    http.GET("/DownloadImg", [](const HttpContextPtr& ctx) {

//        std::uint8_t aes_key[] =  {0x5a,0x2c,0xa4,0xe2,0xdd,0x87,0x3a,0x85,0xd7,0xc4,0xa3,0xc6,0xef,0xf1,0x82,0xab};
//        std::string aes_key_str;
//        std::string fileid = "3057020100044b30490201000204c33e1a1b02032f501e02046b845ad3020464b13a0c042432333033663564652d393239642d346335382d626462392d326339613264363261623930020401150a020201000405004c54a200";
//        std::string authkey_str;
//        std::uint8_t authkey[] =  {0x30,0x3e,0x02,0x01,0x01,0x04,0x37,0x30,0x35,0x02,0x01,0x01,0x02,0x01,0x01,0x02,
//                                   0x04,0x6f,0x6f,0x63,0xae,0x02,0x01,0x00,0x02,0x01,0x00,0x02,0x04,0x8f,0x87,0x13,
//                                   0x70,0x02,0x03,0x2f,0x77,0xf7,0x02,0x04,0x9b,0xe1,0x2e,0x70,0x02,0x04,0x9d,0xe1,
//                                   0x2e,0x70,0x02,0x04,0x65,0x00,0x4d,0x81,0x02,0x04,0x83,0xc7,0x4a,0xa8,0x04,0x00
//                                 };
        std::string aes_key = ctx->param("aes_key","");
        std::string fileid = ctx->param("fileid","");
        if(aes_key=="" || fileid.size() <=0){
            return ctx->send("param error");
        }
//        std::string aes_key = "5a2ca4e2dd873a85d7c4a3c6eff182ab";
//        std::string fileid = "3057020100044b30490201000204c33e1a1b02032f501e02046b845ad3020464b13a0c042432333033663564652d393239642d346335382d626462392d326339613264363261623930020401150a020201000405004c54a200";
        std::string aes_key_str;
        aes_key_str.resize(aes_key.size()/2+1);
        aes_key_str.resize(Utils::string2byte(aes_key,( std::uint8_t*)aes_key_str.data()));

        std::string result =  wsBridge.WX_DonwloadImg(aes_key_str,fileid);

        return ctx->send(std::move(result));
    });

    http.GET("/init_CNDDNS", [](const HttpContextPtr& ctx) {
        nlohmann::json ret ;
        wsBridge.WX_Init_CDNDNS(ret);
        std::string ret_str = ret.dump(-1,' ',false,JSON::error_handler_t::ignore);
        return ctx->send(std::move(ret_str));
    });

//    用于获取好友信息 群成员信息(群成员昵称，群成员wxid)
    http.GET("/GetContact", [](const HttpContextPtr& ctx) {
        std::string userID = ctx->param("wxid","");
        if(userID=="" || userID.size() <=0){
            return ctx->send("param error");
        }
//        auto ret = wsBridge.WX_GetContact(userID);
        std::string ret= wsBridge.WX_GetContact(userID);
        return ctx->send(ret);
    });

    http.GET("/AddChatroomMember", [](const HttpContextPtr& ctx) {
        std::string roomId = ctx->param("roomId","");
        std::string userID_str = ctx->param("userID","");

//        std::vector<std::string> userID={"wxid_4zr616ir6fi122","wxid_8d124lgymw8o22"};
        if(roomId.size()<=0 || userID_str.size() <=0){
            return ctx->send("param error");
        }
        vector<std::string> userID;
        Utils::splitString(userID_str,';',userID);

//        std::string roomId="49729349084@chatroom";
//        std::vector<std::string> userID={"wxid_4zr616ir6fi122","wxid_8d124lgymw8o22"};
        wsBridge.WX_AddChatroomMember(roomId,userID);
        return ctx->send("pong");
    });
    http.GET("/InitContact", [](const HttpContextPtr& ctx) {
        std::string current_wx_contact_seq_str = ctx->param("current_wx_contact_seq","");
        std::string current_chatroom_contact_seq_str = ctx->param("current_chatroom_contact_seq","");
        if(current_wx_contact_seq_str.size()<=0 || current_chatroom_contact_seq_str.size() <=0){
            return ctx->send("param error");
        }
        std::uint32_t current_wx_contact_seq = std::stoi(current_wx_contact_seq_str);
        std::uint32_t current_chatroom_contact_seq = std::stoi(current_chatroom_contact_seq_str);

        std::string ret = wsBridge.WX_InitContact(current_wx_contact_seq,current_chatroom_contact_seq);
        return ctx->send(std::move(ret));
    });
    http.GET("/DelChatRoomMember", [](const HttpContextPtr& ctx) {
        std::string roomId = ctx->param("roomId","");
        std::string userID_str = ctx->param("userID","");

//        std::vector<std::string> userID={"wxid_4zr616ir6fi122","wxid_8d124lgymw8o22"};
        if(roomId.size()<=0 || userID_str.size() <=0){
            return ctx->send("param error");
        }
        vector<std::string> userID;
        Utils::splitString(userID_str,';',userID);


//        std::string roomId="49729349084@chatroom";
//        std::vector<std::string> userID={"wxid_4zr616ir6fi122","wxid_8d124lgymw8o22"};
        wsBridge.WX_DelChatRoomMember(roomId,userID);
        return ctx->send("pong");
    });


    http.GET("/RevokeMsg", [](const HttpContextPtr& ctx) {//127.0.0.1:8080/RevokeMsg?from_wxid=wxid_lkrrzokc7epn22&to_wxid=wxid_4zr616ir6fi122&ser_msg_id=7661827249227098892
//        std::string room_id = ctx->param("room_id","");
        std::string from_wxid = ctx->param("from_wxid","");
        std::string to_wxid = ctx->param("to_wxid","");
        std::string SvrNewMsgId_str = ctx->param("ser_msg_id","");
        std::uint64_t SvrNewMsgId =std::stoull(SvrNewMsgId_str.c_str());

//        std::string roomId="49729349084@chatroom";
//        std::vector<std::string> userID={"wxid_4zr616ir6fi122","wxid_8d124lgymw8o22"};
//        wsBridge.WX_AddChatroomMember(roomId,userID);
//        wsBridge.WX_DelChatRoomMember(roomId,userID);
//        wsBridge.WX_RevokeMsg("wxid_lkrrzokc7epn22", "wxid_4zr616ir6fi122","");
        wsBridge.WX_RevokeMsg(from_wxid, to_wxid,SvrNewMsgId);
        return ctx->send("pong");
    });

    WebSocketService ws;

    ws.onopen = [this](const WebSocketChannelPtr &channel, const HttpRequestPtr &req){
        this->onopen(channel,req);
    };
    ws.onmessage = [this](const WebSocketChannelPtr& channel, const std::string& msg) {
        this->onmessage(channel,msg);
    };
    ws.onclose = [this](const WebSocketChannelPtr& channel) {


        this->onclose(channel);
    };

    server.port = DEFAULT_PORT;

    server.registerHttpService(&http);
    server.registerWebSocketService(&ws);
    server.run();
}
void WS_Server::onopen(const WebSocketChannelPtr &channel, const HttpRequestPtr &req) {
    std::string newUUID= Utils::GenerateUUID();
    channel->send("connect ok");
    printf("onopen: GET %s\n", req->Path().c_str());
    spdlog::info("new connection {}",  newUUID) ;
    auto ctx=channel->newContextPtr<WS_Context>();
    ctx->Init(newUUID,channel);
    Connections.insert(std::pair<std::string,WebSocketChannelPtr>(newUUID,channel));

    wsBridge.set_WeChatBridge(weChatBridge);
}


void WS_Server::onmessage(const WebSocketChannelPtr &channel, const string &msg) {
    auto ctx = channel->getContextPtr<WS_Context>();
    JSON json;
    try {
        json = JSON::parse(
                msg);
    }catch (JSON::exception& e){
        spdlog::error("unkonw data {}",msg);
        return;
    }
    if(!json.contains("type")){
        spdlog::error("nedd request with json type   -> : {} ",msg);
        return;
    }
    uint32_t type=json["type"];

    switch (type) {
        case SocketType::Init:{
            spdlog::info("websocket init success");
            channel->send("websocket init success");
            break;
        }
        case SocketType::SendMsg:{
/*
 * at_list 可选 带艾特的时候必须在msg_content也加上艾特的用户昵称
 *
  {
  "type": 2 ,
  "msg_content" : "@zhuzhuxia1111?@zhuzhu-xia?123",
  "to_wxid": "4972934xxxx@chatroom",
  "at_list": ["wxid_lkrrzxxxx22","wxid_8d124xxxx8o22"]
 }

 {
  "type": 2 ,
  "msg_content" : "@zhuzhuxia1111?@zhuzhu-xia?123",
  "to_wxid": "49729349084@chatroom",
  "at_list": ["wxid_lkrrzokc7epn22","wxid_8d124lgymw8o22"]
 }
 * */
            std::string msg_content=json["msg_content"];
            std::string to_wxid=json["to_wxid"];

            std::vector<std::string> vec_at_list;
            if(json.find("at_list") != json.end()){
                vec_at_list = json["at_list"];
            }
            std::uint32_t client_mgs_id=0x0;
            wsBridge.WX_SendNewMsg(to_wxid,msg_content,client_mgs_id,vec_at_list);
            spdlog::info("websocket send new msg  client_mgs_id : {}",client_mgs_id);
            JSON retJson;
            retJson["client_mgs_id"]  = client_mgs_id;

            channel->send(retJson.dump());
            break;
        }
    }


    spdlog::info("webscoket onmessage : {}",json.dump());
}
void WS_Server::onclose(const WebSocketChannelPtr &channel) {
    auto ctx = channel->getContextPtr<WS_Context>();
    printf("onclose\n");

    std::erase_if(Connections, [&](const auto &item) {
        auto const& [key, value] = item;
        spdlog::info("onclose : {}",key);
        return key==ctx->UUID;
    });
}




