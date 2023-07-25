//
// Created by 28264 on 2023/7/13.
//

#ifndef WEHELPER_CDNPACK_H
#define WEHELPER_CDNPACK_H
#include "../common/ByteBuffer.hpp"
#include <vector>

class CDNPack {
    std::uint32_t seq=0;
    std::uint64_t taskid=1398858313023582138;
    struct MapTyep{
        std::string key;
        std::string value;
    };


    std::vector<MapTyep> requestItem={
            {"ver","1"},
            {"weixinnum","1"},//1869570990
            {"province","16"},
            {"city","19"},
            {"isp","3"},
            {"rulekey","1_0_0_0_-1"},
            {"expectrulekey","1_1_2_2_-1"},
            {"seq","0"},
            {"clientversion","1661534743"},
            {"clientostype","Windows 10 x64"},
            {"authkey","authkey"},//0x40
            {"nettype","1"},
            {"acceptdupack","1"},
            {"rsaver","1"},
            {"rsavalue","rsavalue"},
            {"filetype","2"},
            {"wxchattype","0"},
            {"taskid","0"},//1398858313023582138
            {"totalsize","16"},
            {"rawtotalsize","0"},
            {"fileid","fileid"},
            {"lastretcode","0"},
            {"cli-quic-flag","0"},
            {"wxmsgflag",""},
            {"wxautostart","1"},
            {"downloadbehavor","1"},
            {"downpicformat","1"},//
            {"offset","0"},
            {"largesvideo","0"},
            {"sourceflag","0"},

    };

public:
    bb::ByteBuffer PackHeader(  std::vector<MapTyep>& innerPackage,
                                std::uint32_t UIN,
                                std::uint16_t flag);
    bb::ByteBuffer AskCdnReadyPack( std::uint32_t UIN,std::string& authkey);
    bb::ByteBuffer RealCdnRequestPack( std::uint32_t UIN,
                                       std::string& aes_key,
                                       std::string& authkey ,
                                       std::string &fileid);

};


#endif //WEHELPER_CDNPACK_H
