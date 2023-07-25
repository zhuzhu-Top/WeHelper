//
// Created by 28264 on 2023/6/14.
//

#ifndef WEHELPER_WXPROTOBUF_H
#define WEHELPER_WXPROTOBUF_H
#include "../include/pub_include.h"
#include "../common/ProtobufHelper.h"

#include "../common/ByteBuffer.hpp"

enum E_ClientVersion{
    V_3_9_2_23 = 0x63090217,

};


class WxProtobuf {
    using JSON = nlohmann::json;

    static ProtobufHelper protobufHelper;

public:
    static uint32_t newMsg(std::vector<uint8_t>& out_buff,
                           std::string& to_wxid,
                           std::string& msg_content,
                            std::uint32_t& client_mgs_id,
                           const std::vector<std::string>& at_list={});

    static uint32_t addChatroomMember(        vector<uint8_t> &out_buff,
                                              std::string& devicesID,
                                              std::uint32_t Uin,
                                              std::string& rooid,
                                              std::vector<std::string>& userIds);
    static uint32_t delChatroomMember(        vector<uint8_t> &out_buff,
                                              std::string& devicesID,
                                              std::uint32_t Uin,
                                              std::string& rooid,
                                              std::vector<std::string>& userIds);
    static uint32_t initContack(        vector<uint8_t> &out_buff,
                                        std::string& username,
                                        std::uint32_t currentChatRoomContactSeq,
                                        std::uint32_t currentWxcontactSeq
                                              );

    static uint32_t getContack(        vector<uint8_t> &out_buff,
                                       string &devicesID,
                                       std::uint32_t Uin,
                                       string &wxid);
    static uint32_t getCDNDNS(vector<uint8_t> &out_buff,
                                       string &devicesID,
                                       std::uint32_t Uin
                                      );
    static uint32_t revokeMsg(
            vector<uint8_t> &out_buff,
            std::string from_wxid,
            std::string to_wxid,
            std::string devicesID,
            std::uint32_t Uin,
            std::uint64_t SvrNewMsgId
                    );

    static void Parse_CDNDnsResponse();

    static JSON Parse_NewSyncResponse(std::uint8_t *pb_data,
                                      std::uint32_t pb_len,std::string& ret_json_str);
};


#endif //WEHELPER_WXPROTOBUF_H
