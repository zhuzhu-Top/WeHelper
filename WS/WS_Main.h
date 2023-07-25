//
// Created by 28264 on 2023/6/5.
//

#ifndef WEHELPER_WS_MAIN_H
#define WEHELPER_WS_MAIN_H



class WS_Main{


public:
    static void Init();

    static void SendMsg2Client(std::string& msg);
};

#endif //WEHELPER_WS_MAIN_H
