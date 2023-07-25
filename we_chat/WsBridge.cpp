//
// Created by 28264 on 2023/6/14.
//

#include "WsBridge.h"


#include "../core/BuildPackage.h"
#include "../common/ProtobufHelper.h"

#include "../we_chat/WXShortLinkMessage.h"
#include "../core/WxProtobuf.h"
#include "WXCGIUrl.h"




#define WeChatShotlinkAddr "szextshort.weixin.qq.com"
static ProtobufHelper Pb_Helper;


std::string cgi2string(uint32_t cgi){
    return Cgi_List.find(cgi) != Cgi_List.end() ? Cgi_List[cgi] : std::format("unknown cgi {}",cgi);
}
std::string ReqId2StringFun(uint32_t reqId){
    if(ReqId2String.size()==0){
        for (auto item  : cmdID2ReqId) {
            ReqId2String[item.second] = Cgi_List[item.first];
        }
    }
    return ReqId2String.find(reqId) !=ReqId2String.end() ? ReqId2String[reqId] : "unknown reqId";

}

void
WsBridge::LongLinkSend( std::vector<uint8_t>& vec_pb_data,std::uint32_t pb_len,std::uint16_t cmdID) {
    BuildPackage buildPackage(weChatBridge);
    bb::ByteBuffer HeadByteBuff(0x200); //封装的内部头
    bb::ByteBuffer OutPackage(0x200);

    buildPackage.ConstructInnerPackage(HeadByteBuff,vec_pb_data,pb_len,cmdID);
    buildPackage.ConstructTlsPackage(HeadByteBuff, weChatBridge->TLS_Random_SeqId,OutPackage,cmdID);
    weChatBridge->TLS_Random_SeqId++;

    uint8_t* send_buf = new uint8_t[OutPackage.size()];
    OutPackage.getBytes(send_buf,OutPackage.size());
    if(weChatBridge->LonglinkHand.empty()){
        spdlog::error("LonglinkHand is empty");
        goto  out;
    }
    weChatBridge->SocketSend(std::stoi(weChatBridge->LonglinkHand, nullptr,16),send_buf,OutPackage.size());
    out:
    delete[] send_buf;
}


void WsBridge::WX_SendNewMsg(std::string to_wxid,std::string msg_content,std::uint32_t& client_mgs_id,const std::vector<std::string>& vec_at_list) {

    BuildPackage buildPackage(weChatBridge);

    bb::ByteBuffer HeadByteBuff(0x200); //封装的内部头
    bb::ByteBuffer OutPackage(0x200);
//    uint32_t pb_len=0;
    std::vector<uint8_t> vec_pb_data;

//    shared_ptr<uint8_t[]> pb_data = ProtobufHelper::newMsg(pb_len);
    uint32_t pb_len = WxProtobuf::newMsg(vec_pb_data,to_wxid,msg_content,client_mgs_id,vec_at_list);
    vec_pb_data.resize(pb_len);
//    memcpy(vec_pb_data.data(),pb_data.get(),pb_len);
    spdlog::debug("send msg pb : \r\n {}",spdlog::to_hex(vec_pb_data));

    buildPackage.ConstructInnerPackage(HeadByteBuff,vec_pb_data,pb_len,micromsg_bin_newsendmsg);
    buildPackage.ConstructTlsPackage(HeadByteBuff, weChatBridge->TLS_Random_SeqId,OutPackage,micromsg_bin_newsendmsg);
    weChatBridge->TLS_Random_SeqId++;

    uint8_t* send_buf = new uint8_t[OutPackage.size()];
    OutPackage.getBytes(send_buf,OutPackage.size());
    if(weChatBridge->LonglinkHand.empty()){
        spdlog::error("LonglinkHand is empty");
        goto  out;
    }
    weChatBridge->SocketSend(std::stoi(weChatBridge->LonglinkHand, nullptr,16),send_buf,OutPackage.size());


    weChatBridge->SendKeyIVSeq_ToJs();

out:
    delete[] send_buf;

}

void
WsBridge::WX_RevokeMsg(        std::string from_wxid,
                               std::string to_wxid,
                               std::uint64_t SvrNewMsgId) {


    std::vector<uint8_t> vec_pb_data;
    BuildPackage buildPackage(weChatBridge);
    vector<uint8_t> pb_data;

    uint32_t pb_len = WxProtobuf::revokeMsg(
                pb_data,
//                "wxid_8d124lgymw8o22",
                from_wxid,
                to_wxid,
                weChatBridge->devicesId,
                weChatBridge->G_UIN,
                SvrNewMsgId   //server msg id
//                4844828737173425018   //server msg id
                );
    pb_data.resize(pb_len);
    bb::ByteBuffer inner_body;
    buildPackage.ConstructInnerPackage(inner_body,pb_data,pb_len,micromsg_bin_revokemsg);

//    WXShortLinkMessage wx("szextshort.weixin.qq.com","/cgi-bin/micromsg-bin/revokemsg",inner_body);
    WXShortLinkMessage wx(WeChatShotlinkAddr,"/cgi-bin/micromsg-bin/revokemsg",inner_body);
    wx.SetWechatBridge(weChatBridge);
    wx.ShortLinkPack();
    bb::ByteBuffer resp = wx.Post();

}

void
WsBridge::WX_AddChatroomMember(
        string &roomId,
        vector<std::string> &userId) {
    vector<uint8_t> vec_pb_data;

    uint32_t pb_len = WxProtobuf::addChatroomMember(
            vec_pb_data,
            weChatBridge->devicesId,
            weChatBridge->G_UIN,
            roomId,
            userId
    );
    LongLinkSend(vec_pb_data,pb_len,micromsg_bin_addchatroommember);

}

void WsBridge::WX_DelChatRoomMember(
        string &roomId,
        vector<std::string> &userId) {

    std::vector<uint8_t> vec_pb_data;
    BuildPackage buildPackage(weChatBridge);
    vector<uint8_t> pb_data;

    uint32_t pb_len = WxProtobuf::delChatroomMember(
            vec_pb_data,
            weChatBridge->devicesId,
            weChatBridge->G_UIN,
            roomId,
            userId
    );
    bb::ByteBuffer inner_body;
    buildPackage.ConstructInnerPackage(inner_body,vec_pb_data,pb_len,micromsg_bin_delchatroommember);

    WXShortLinkMessage wx(WeChatShotlinkAddr,Cgi_List[micromsg_bin_delchatroommember],inner_body);
    wx.SetWechatBridge(weChatBridge);
    wx.ShortLinkPack();
    bb::ByteBuffer resp = wx.Post();

    int aaa=0;
}
std::string
WsBridge::WX_InitContact(
        std::uint32_t current_wx_contact_seq,
        std::uint32_t current_chatroom_contact_seq
        ) {

    std::vector<uint8_t> vec_pb_data;
    BuildPackage buildPackage(weChatBridge);
    vector<uint8_t> pb_data;

    uint32_t pb_len = WxProtobuf::initContack(
            vec_pb_data,
            weChatBridge->wxid,
            current_chatroom_contact_seq,
            current_wx_contact_seq
    );
    bb::ByteBuffer inner_body;
    buildPackage.ConstructInnerPackage(inner_body,vec_pb_data,pb_len,micromsg_bin_initcontact);

    WXShortLinkMessage wx(WeChatShotlinkAddr,Cgi_List[micromsg_bin_initcontact],inner_body);
    wx.SetWechatBridge(weChatBridge);
    wx.ShortLinkPack();
    bb::ByteBuffer resp = wx.Post();
    std::unique_ptr<bb::ByteBuffer> resp_ptr= std::make_unique<bb::ByteBuffer>(resp);
    struct Header resp_header;

    bb::ByteBuffer parsed_body;
    if(!buildPackage.UnpackPackage(resp_ptr,resp_header,parsed_body)){
        return "";
    }
    JSON json_ret;
    Pb_Helper.parse_pb(parsed_body.getPtr(),parsed_body.size(),json_ret);
    spdlog::info("get contact ret : {}",parsed_body.getString());
    return std::move(json_ret.dump(-1,' ',false,JSON::error_handler_t::ignore));
}

std::string
WsBridge::WX_GetContact(
        std::string userId) {
    std::vector<uint8_t> vec_pb_data;
    BuildPackage buildPackage(weChatBridge);
    vector<uint8_t> pb_data;

    uint32_t pb_len = WxProtobuf::getContack(
            vec_pb_data,
            weChatBridge->devicesId,
            weChatBridge->G_UIN,
            userId
    );
    bb::ByteBuffer inner_body;
    buildPackage.ConstructInnerPackage(inner_body,vec_pb_data,pb_len,micromsg_bin_getcontact);

    WXShortLinkMessage wx(WeChatShotlinkAddr,Cgi_List[micromsg_bin_getcontact],inner_body);
    wx.SetWechatBridge(weChatBridge);
    wx.ShortLinkPack();
    bb::ByteBuffer resp = wx.Post();
    std::unique_ptr<bb::ByteBuffer> resp_ptr= std::make_unique<bb::ByteBuffer>(resp);
    struct Header resp_header;

    bb::ByteBuffer parsed_body;

    if(!buildPackage.UnpackPackage(resp_ptr,resp_header,parsed_body)){
        return "";
    }

    JSON json_ret;
    Pb_Helper.parse_pb(parsed_body.getPtr(),parsed_body.size(),json_ret);
    spdlog::info("get contact ret : {}",parsed_body.getString());
    return std::move(json_ret.dump(-1,' ',false,JSON::error_handler_t::ignore));
}

void
WsBridge::WX_Init_CDNDNS(nlohmann::json& retValue) {
    std::vector<uint8_t> vec_pb_data;
    BuildPackage buildPackage(weChatBridge);
    vector<uint8_t> pb_data;

    uint32_t pb_len = WxProtobuf::getCDNDNS(
            vec_pb_data,
            weChatBridge->devicesId,
            weChatBridge->G_UIN
    );
    bb::ByteBuffer inner_body;
    buildPackage.ConstructInnerPackage(inner_body,vec_pb_data,pb_len,micromsg_bin_getcdndns);

    WXShortLinkMessage wx(WeChatShotlinkAddr,Cgi_List[micromsg_bin_getcdndns],inner_body);
    wx.SetWechatBridge(weChatBridge);
    wx.ShortLinkPack();
    bb::ByteBuffer resp = wx.Post();

    std::unique_ptr<bb::ByteBuffer> resp_ptr= std::make_unique<bb::ByteBuffer>(resp);
    struct Header resp_header;

    bb::ByteBuffer parsed_body;
    if(!buildPackage.UnpackPackage(resp_ptr,resp_header,parsed_body)){
        return ;
    }
    Pb_Helper.parse_pb(parsed_body.getPtr(),parsed_body.size(),retValue);
    LOGD("cnddns  : {}",parsed_body.getString());
    LOGD("cnddns  : {}",retValue.dump(-1,' ',false,JSON::error_handler_t::ignore));
    weChatBridge->dns_authkey_str= retValue["2"]["8"]["2"];
    {
        auto tmp_6 =  retValue["2"]["6"];

        weChatBridge->dns_server_ip = tmp_6[0]["1"];
    }


    spdlog::info("dns ip        {}",weChatBridge->dns_server_ip);
    spdlog::info("dns auth key  {}",weChatBridge->dns_authkey_str);

    weChatBridge->dns_Initialized=true;

}




