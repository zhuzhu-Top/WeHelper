//
// Created by 28264 on 2023/6/14.
//

#ifndef WEHELPER_WSBRIDGE_H
#define WEHELPER_WSBRIDGE_H

#include <nlohmann/json.hpp>
#include "../common/ByteBuffer.hpp"

class WsBridge {

    class WeChatBridge* weChatBridge;

    using JSON = nlohmann::json;
public:

    WsBridge(){};


    void WX_SendNewMsg(std::string to_wxid,std::string msg_content,std::uint32_t& client_mgs_id,const std::vector<std::string>& vec_at_list);
    void WX_RevokeMsg(  std::string from_wxid,std::string to_wxid, std::uint64_t SvrNewMsgId);
    void WX_AddChatroomMember(std::string& roomId,std::vector<std::string>& userId);
    std::string WX_GetContact(std::string userId);
    std::string WX_InitContact( std::uint32_t current_wx_contact_seq,std::uint32_t current_chatroom_contact_seq);
    void WX_DelChatRoomMember(std::string& roomId,std::vector<std::string>& userId);
    void WX_Init_CDNDNS(nlohmann::json& retValue);

    std::string WX_DonwloadImg( std::string& aes_key_str,std::string& fileid);

    void LongLinkSend(std::vector<uint8_t>& vec_pb_data,std::uint32_t pb_len,std::uint16_t cmdID);

    void set_WeChatBridge(class WeChatBridge* weChatBridge){
        this->weChatBridge=weChatBridge;
    }
};


#endif //WEHELPER_WSBRIDGE_H
