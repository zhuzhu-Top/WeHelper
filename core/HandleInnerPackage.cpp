//
// Created by 28264 on 2023/6/21.
//

#include "HandleInnerPackage.h"

#include "../include/pub_include.h"
#include "../common/ProtobufHelper.h"

#include "../WS/WS_Main.h"
static ProtobufHelper pb_helper;

void
HandleInnerPackage::HandleGetCDNDns(
        bb::ByteBuffer &pb_data) {

    spdlog::info("get dns pb -> {}",pb_data.getString());

}

void
HandleInnerPackage::HandleSendMsgResponse(
        bb::ByteBuffer &pb_data,bool is_from_encrypt) {
//    spdlog::debug(R"(
//[     *** recv msg ***  ==>  {}  ]
//| pb data : {}
//[     *** recv msg *** End ]
//)",is_from_encrypt ? "Request" : "Response",pb_data.getString());

    JSON js;
    pb_helper.parse_pb(pb_data.getPtr(),pb_data.size(),js);



    if(is_from_encrypt){
        return;
    }

    std::uint64_t newMsgId=js["3"]["8"].get<std::uint64_t>();

    auto& item_3_2 = js.at("3").at("2");
    std::string toUsetName;
    if(item_3_2.is_string()){
        toUsetName=item_3_2.get<std::string>();
    }else{
        toUsetName =item_3_2["1"].get<std::string>();
    }



    spdlog::debug(R"(
[     *** recv msg ***  ==>  {}  ]
| pb data  : {}
| newMsgId : {}
|toUsetName: {}
[     *** recv msg *** End ]
)",is_from_encrypt ? "Request" : "Response",pb_data.getString(),newMsgId,toUsetName);

    JSON json_to_client;
    json_to_client["content_from"] = is_from_encrypt ? "Request" : "Response";
    json_to_client["pb_data"] = pb_data.getString();
    json_to_client["newMsgId"] =newMsgId;
    json_to_client["toUsetName"] =toUsetName;

    std::string str_to_client= json_to_client.dump(-1,' ',false,JSON::error_handler_t::ignore);
    WS_Main::SendMsg2Client(str_to_client);

}
