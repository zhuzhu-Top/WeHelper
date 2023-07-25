//
// Created by 28264 on 2023/6/21.
//

#ifndef WEHELPER_HANDLEINNERPACKAGE_H
#define WEHELPER_HANDLEINNERPACKAGE_H


#include "../common/ByteBuffer.hpp"
class HandleInnerPackage {




public:
    static void HandleGetCDNDns(bb::ByteBuffer &pb_data);
    static void HandleSendMsgResponse(bb::ByteBuffer &pb_data,bool is_from_encrypt);
};


#endif //WEHELPER_HANDLEINNERPACKAGE_H
