#include "WS_Server.h"
#include "WS_Main.h"



WS_Server* wsServer;


void WS_Main::Init(){
    wsServer=new WS_Server();
    wsServer->run();

}

void WS_Main::SendMsg2Client(std::string &msg) {
    for(auto& [UUID,channel] : wsServer->Connections){
        channel->send(msg);

    }
}



