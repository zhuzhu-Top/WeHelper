#include "core.h"

//
// Created by 28264 on 2023/5/23.
//

#include "../we_chat/WeChatBridge.h"








Script::Script(FridaScript* script,OnMessageCallbackFun onMessageCallback):_impl(script),onMessageCallbackFun(onMessageCallback) {
//    onMessageCallbackFun=onMessageCallback;

//    mtx = std::make_unique<std::mutex>();
//    cv = std::make_unique<std::condition_variable>();

    HandleMessageThread=std::jthread([this]() {
        Loop_HandleMessage();
    });

    g_signal_connect (script, "message", G_CALLBACK(on_message), this);
}
//TODO
JSON Script::list_exports() {
//    frida_script_post(_impl,)
    JSON args={

    };
    return _rpc_request(args);

}

JSON Script::_rpc_request(JSON args) {
    if(!is_destroyed()){
        std::promise<RPCResult> rpc_promise;
        std::unique_lock<std::mutex> lock(mtx);
        auto request_id=_next_request_id++;
        On_MessageSync.insert({request_id,std::move(rpc_promise)});
        lock.unlock();
        LOGD("send rpc req  id-> {}",request_id);
        _send_rpc_call(request_id,args);
       std::promise<RPCResult>&  ret_promise= On_MessageSync.at(request_id);
       std::future<RPCResult> result_future= ret_promise.get_future();
       auto future_status=  result_future.wait_for(std::chrono::seconds(RPC_TIMEOUT));
       if(future_status==std::future_status::ready){
           auto result=result_future.get();
           result.finished= true;
           return result.value;
       } else{
//           auto result=result_future.get();
//           result.finished= false;
           JSON result;
           result["error"]="time out";
           return result;
       }
    }else{
        return "frida_script_is_destroyed";
    }

}

//uint32_t Script::_append_pending(CallbackFun callbackFun) {
//    auto request_id = _next_request_id++;
////    std::unique_lock<std::mutex> lock(mtx); // 获取互斥锁
//
//    _pending.emplace_back(request_id,callbackFun);
////    lock.unlock(); // 释放互斥锁
////    cv.notify_one(); // 通知等待线程
//    return request_id;
//}

void Script::_send_rpc_call(uint32_t request_id, JSON& args) {

    JSON message={"frida:rpc",request_id};
    for(auto item : args){
        message.push_back(item);
    }

    post(message);

}

void Script::post(JSON& message) {
    std::string json_data;
    json_data = message.dump();
    //'["frida:rpc", 1, "call", "add", [1, 2]]'
    frida_script_post(_impl,json_data.c_str(), nullptr);

}

JSON Script::JS_Call(const char* method_name,JSON call_args ) {
//    JSON args={
//            "call",
//            "add",
//            {1,2},
//    };
    JSON args={
            "call",
            method_name,
            call_args,
    };
    return _rpc_request(std::move(args));
}

void Script::on_message(FridaScript *script, const gchar *message, GBytes *data, gpointer user_data) {
    Script* thisPtr = (Script*)user_data;
//    LOGD("Script::on_message ras message {}" , message);
    if(thisPtr == nullptr)
        throw "Script is nullptr";
    if(message==nullptr){spdlog::info("on_message recv empty message");};


    JSON js_data = JSON::parse(message);
    string mtype=js_data.at("type");
    if (mtype=="error"){
        LOGD(message);
        return;
    }


    JSON payload=js_data.at("payload");


    if(mtype=="log"){
        //TODO

    }else if(mtype=="send" &&  !payload.empty() && payload.is_array() ){  //返回payload 是数组的处理
        if(payload.at(0)=="frida:rpc"){
            auto result = RPCResult();

            int request_id = payload[1]; //请求的ID
            string operation = payload[2]; //请求的响应结果
            JSON params = JSON(payload.begin()+3,payload.end());

            result.value=params;
            result.finished = true;

            auto& rpc_item=thisPtr->On_MessageSync.at(request_id);
            rpc_item.set_value(std::move(result));
//            thisPtr->_on_rpc_message(request_id,operation,params);
            return;
        }
    }else if(mtype=="send" &&  !payload.empty() && (payload.is_array() || payload.is_object())){
        thisPtr->pushMsg2CallBack(payload);
//        thisPtr->onMessageCallbackFun(script, message, payload,data, user_data);
        return;
    }
    string str_message(to_string(payload));
    str_message = std::regex_replace(str_message, std::regex("\\\\r\\\\n"), "\r\n");
    LOGD("on_message : {} {}",mtype,str_message);
//    spdlog::debug();
//    std::cout<< "on_message : "<<mtype<<"  --> " << payload<<std::endl;

}

void Script::Loop_HandleMessage() {

    std::jthread jthread1;

    while(true){

        if(!deque_task.empty())
        {

            std::unique_lock<std::mutex> lock(dq_lok);
            JSON message =deque_task.front();
            deque_task.pop_front();

            lock.unlock();
            onMessageCallbackFun(nullptr, nullptr,message, nullptr, nullptr);

        }

    }


}

//void Script::_on_rpc_message(int request_id, string operation, JSON params) {
//    for (auto item = _pending.begin(); item != _pending.end(); ++item) {
//        if(item->first==request_id){
//
//            if(operation=="ok") {
//                auto CallBack = item->second;
//                spdlog::info("rpc {} execute ok",request_id);
//                CallBack(params);
//
//            }else{
//                std::cout<< "_on_rpc_message null handle "<<std::endl;
//
//            }
//            //无论响应是否成功，都清除这个回调
//            _pending.erase(item);
//            return;
//        }
//    }
//
//}





GCancellable *Cancellable::get_current() {
    return g_cancellable_get_current();
}
