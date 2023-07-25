//
// Created by 28264 on 2023/5/23.
//

#ifndef WEHELPER_CORE_H
#define WEHELPER_CORE_H

#include "frida-core.h"

#include "pub_include.h"
#include <csignal>

#define RPC_TIMEOUT 5

using namespace std;
using JSON = nlohmann::json;




struct RPCResult{
    bool finished;
    JSON value;
    string error;
};

class Cancellable{
    GCancellable * handle;



public:
    Cancellable(){
        handle = g_cancellable_new ();
    }
    GCancellable* get_current();

};

typedef std::function<void(FridaScript * script,const gchar * message,JSON& payload,GBytes * data,gpointer user_data)> OnMessageCallbackFun;
class Script{

//    typedef std::function<void(JSON)> CallbackFun;

    OnMessageCallbackFun onMessageCallbackFun;

    FridaScript*  _impl;
//    std::unique_ptr<std::mutex> mtx;
    std::mutex mtx;
//    std::unique_ptr<std::condition_variable> cv;
    uint32_t _next_request_id=1;

    static void on_message (FridaScript * script,
                            const gchar * message,
                            GBytes * data,
                            gpointer user_data);

    void _send_rpc_call(uint32_t request_id,JSON& args);
    JSON _rpc_request(JSON);
    void post(JSON&);
//    void _on_rpc_message(int request_id,string operation,JSON params);

//    uint32_t _append_pending(CallbackFun callbackFun);
    void Loop_HandleMessage();

    std::mutex dq_lok;
    std::deque<JSON> deque_task;
    std::jthread HandleMessageThread;

public:
    std::map<uint32_t ,std::promise<RPCResult>> On_MessageSync;

    Script(FridaScript* script,OnMessageCallbackFun onMessageCallback);
    JSON JS_Call(const char* method_name,JSON args);
    JSON list_exports();
    gboolean is_destroyed(){
        return frida_script_is_destroyed(_impl);
    }

    void __inline pushMsg2CallBack(JSON message){
        std::unique_lock<std::mutex> lock(dq_lok);
        deque_task.push_back(std::move(message));
        lock.unlock();
    }

};



#endif //WEHELPER_CORE_H
