//
// Created by 28264 on 2023/5/31.
//

#ifndef WEHELPER_WXCGIURL_H
#define WEHELPER_WXCGIURL_H

#include "../include/pub_include.h"



//CMD ID
#define micromsg_bin_uploadmsgimg 110
#define micromsg_bin_addchatroommember 120
#define micromsg_bin_delchatroommember 179
#define micromsg_bin_getcontact 182
#define micromsg_bin_newsync 138
#define micromsg_bin_statusnotify 251
#define micromsg_bin_getcdndns 379
#define micromsg_bin_heartbeat 518
#define micromsg_bin_newsendmsg 522
#define micromsg_bin_revokemsg 594
#define micromsg_bin_initcontact 851


static std::map<std::uint32_t,std::string> Cgi_List={
        {micromsg_bin_newsync,"/cgi-bin/micromsg-bin/newsync"},
        {micromsg_bin_newsendmsg,"/cgi-bin/micromsg-bin/newsendmsg"},
        {micromsg_bin_heartbeat,"/cgi-bin/micromsg-bin/heartbeat"},
        {micromsg_bin_getcdndns,"/cgi-bin/micromsg-bin/getcdndns"},
        {micromsg_bin_statusnotify,"/cgi-bin/micromsg-bin/statusnotify"},
        {micromsg_bin_uploadmsgimg,"/cgi-bin/micromsg-bin/uploadmsgimg"},
        {micromsg_bin_addchatroommember,"/cgi-bin/micromsg-bin/addchatroommember"},
        {micromsg_bin_delchatroommember,"/cgi-bin/micromsg-bin/delchatroommember"},
        {micromsg_bin_getcontact,"/cgi-bin/micromsg-bin/getcontact"},
        {micromsg_bin_initcontact,"/cgi-bin/micromsg-bin/initcontact"},

};

static std::map<std::uint16_t,std::uint32_t> cmdID2ReqId={
        {micromsg_bin_newsync,121},
        {micromsg_bin_newsendmsg,237},
        {micromsg_bin_addchatroommember,36},

};
static std::map<std::uint32_t,std::string> ReqId2String={

};

std::string cgi2string(uint32_t cgi);
std::string ReqId2StringFun(uint32_t reqId);



#endif //WEHELPER_WXCGIURL_H
