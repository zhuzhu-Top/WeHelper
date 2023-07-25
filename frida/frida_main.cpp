//
// Created by 28264 on 2023/5/22.
//
#include "frida_main.h"
#include "../common/Utils.h"
#include "../core/BuildPackage.h"

#include "../Net/NetMain.h"


class WeChatBridge* weChatBridge= nullptr;






void OnMessage(FridaScript * script,const gchar * message,JSON& payload,GBytes * data,gpointer user_data){
    if(payload.is_object()){  //返回对象处理
        if ( payload.contains("application_data_key_expansion")){
            uint32_t  len =payload["application_data_key_expansion"]["len"];
            string m_data=payload["application_data_key_expansion"]["data"];
            spdlog::error("application_data_key_expansion len : {} data : {} ",len,m_data);

            weChatBridge->On_application_data_key_expansion(std::move(m_data));


//            auto thr=std::jthread([](){
//                std::this_thread::sleep_for(std::chrono::seconds(5));
//                BuildPackage Buid(weChatBridge);
////                PackInnerHeader(weChatBridge);
//                spdlog::error("send package");
////                    std::this_thread::sleep_for(std::chrono::seconds(3));
//            });
//            thr.detach();
//            weChatBridge.On_application_data_key_expansion(m_data);
            //            WeChatBridge::On_application_data_key_expansion(m_data);
        }else if(payload.contains("TLS_AESGCM")){

            string type=payload["TLS_AESGCM"]["type"];
//            string aes_gcm_key=payload["TLS_AESGCM"]["key"];
//            string plainTxt=payload["TLS_AESGCM"]["plainTxt"];
//            uint32_t plainTxt_len=payload["TLS_AESGCM"]["plainTxt_len"];
//            string aes_gcm_iv=payload["TLS_AESGCM"]["iv"];
//            string aes_gcm_aad=payload["TLS_AESGCM"]["aad"];
//            string aes_gcm_ret_data=payload["TLS_AESGCM"]["ret_data"];
            if(type=="Enctypt"){
                weChatBridge->On_aes_gcm_enc(payload);
            }else{
                weChatBridge->On_aes_gcm_dec(payload);
            }
//            LOGD(R"(
//                            TLS_AESGCM:
//                              type   : {}
//                           plainTxt  : {}
//                       plainTxt_len  : {:X}
//                                key  : {}
//                                iv   : {}
//                                aad  : {}
//                           ret_data  : {}
//                         )",type,plainTxt,plainTxt_len,aes_gcm_key,aes_gcm_iv,aes_gcm_aad,aes_gcm_ret_data);
        }else if(payload.contains("LonglinkUnpack")){
            //长连接解包
            string data=payload["LonglinkUnpack"]["data"];
            uint32_t data_len=payload["LonglinkUnpack"]["data_len"];

//            weChatBridge->On_LonglinkUnpack(data,data_len);
        }
        else if(payload.contains("SOCKET_CONNECT")){
            string fd=payload["SOCKET_CONNECT"]["fd"];
            string ip=payload["SOCKET_CONNECT"]["ip"];
            string port=payload["SOCKET_CONNECT"]["port"];
            LOGD(R"(
SOCKET_CONNECT :
        fd    : {}
        ip    : {}
        port  : {}
                         )",fd,ip,port);
        } else if(payload.contains("ScanPSK")){
            JSON ScanPSK=payload["ScanPSK"]["result"];
            std::string psk_addr_str=ScanPSK.begin()->get<std::string>();

            std::uint64_t psk_add= std::stoull(psk_addr_str,
                                               nullptr,16);
            bb::ByteBuffer tmp_buf;
            tmp_buf.resize(0x93);
            weChatBridge->ReadBytes(psk_add,0x93,tmp_buf.getPtr());

            weChatBridge->PSK.resize(103);
            tmp_buf.getInt(); //前四字节不要
            tmp_buf.getBytes(weChatBridge->PSK.data(),weChatBridge->PSK.size());

            weChatBridge->PskAccessKey.resize(0x20);
            tmp_buf.getInt(); //00 00 00 00去掉
            tmp_buf.getInt(); //长度也不要
            tmp_buf.getBytes(weChatBridge->PskAccessKey.data(),weChatBridge->PskAccessKey.size());

            LOGD("Scan get PSK            {} :\r\n {}",psk_addr_str,spdlog::to_hex(weChatBridge->PSK,16));
            LOGD("Scan get PskAccessKey      :\r\n {}",spdlog::to_hex(weChatBridge->PskAccessKey,16));
        }else if(payload.contains("SendBaseInfo")){

            weChatBridge->devicesId=payload["SendBaseInfo"]["devicesID"].get<std::string>();
            weChatBridge->wxid=payload["SendBaseInfo"]["wxid"].get<std::string>();
            spdlog::info("devicesID          : {}",weChatBridge->devicesId);
            spdlog::info("wxid               : {}",weChatBridge->wxid);

        }
        else if(payload.contains("SocketSend")){
            string hand=payload["SocketSend"]["hand"];
            string data=payload["SocketSend"]["data"];
            uint32_t data_len=payload["SocketSend"]["data_len"];
            JSON JS_socket=payload["SocketSend"]["socket"];
            uint32_t port=JS_socket["port"];
            string IP=JS_socket["ip"];
            Utils::RemoveBrackets(IP);
            bool isLongLink= NetConfig::IsLongLink(IP,port);
//            if(isLongLink){
//                weChatBridge->LonglinkHand=hand;
//                spdlog::info("longlink hand ->: {}",hand);
//            }

            if(data.starts_with("17 f1 04")){
                weChatBridge->LonglinkHand=hand;
                spdlog::info("may be  longlink hand ->: {}",hand);
            }

//            if(!weChatBridge->Initialized){
//                if(isLongLink){
//                    spdlog::debug("send data to reset hkdf");//发送错误数据，让微信重新协商密钥
//                    uint8_t dadadada[]={0x68,0x61,0x6e,0x64,0x73,0x68,0x61,0x6b,0x65,0x20,0x6b,0x65,0x79,0x20,0x65,0x78,0x70,0x61,0x6e,0x73,0x69,0x6f,0x6e,0x56,0x49,0xce,0x2f,0x8b,0x8d,0xef,0xca,0x04,0xac,0x4e,0x98,0x3c,0x47,0x14,0x84,0x9b,0x37,0x6f,0x7b,0x8b,0x79,0xa9,0x96,0xbc,0x86,0x1b,0xa6,0x78,0x05,0x13,0x83};
//                    weChatBridge->\(std::stoi(hand, nullptr,16),dadadada,55);
//                    weChatBridge->Initialized= true;
////                    weChatBridge.SocketSend(0x16c8,dadadada,55);
//                }
//
//            }
//            LOGD(R"(SocketSend : hand    : {} data_len  : {:X} socket   : {})",hand,data_len,JS_socket.dump());
            LOGD(R"(
[**************SocketSend : *****]
|        hand    : {}
|        data    : {}
|      data_len  : {:X}
|       socket   : {}
[********************************]
                         )",hand,data,data_len,JS_socket.dump());
        }
        return;
    }

}


void FridaMain(){
    weChatBridge=new WeChatBridge();

    FridaDeviceManager * manager;
    GError * error = NULL;
    FridaDeviceList * devices;
    gint num_devices, i;
    FridaDevice * local_device;
    FridaSession * session;
    std::fstream js_file;
    frida_init ();
    gobject_init();

    const gchar * version=frida_version_string();

    loop = g_main_loop_new (NULL, TRUE);

    signal (SIGINT, on_signal);
    signal (SIGTERM, on_signal);


    manager = frida_device_manager_new ();

    devices = frida_device_manager_enumerate_devices_sync (manager, NULL, &error);
    g_assert (error == NULL);


    local_device = NULL;
    num_devices = frida_device_list_size (devices);
    for (i = 0; i != num_devices; i++)
    {
        FridaDevice * device = frida_device_list_get (devices, i);

        g_print ("[*] Found device: \"%s\"\n", frida_device_get_name (device));

        if (frida_device_get_dtype (device) == FRIDA_DEVICE_TYPE_LOCAL)
            local_device = g_object_ref (device);

        g_object_unref (device);
    }
    g_assert (local_device != NULL);

    FridaBus * fridaBus =frida_device_get_bus(local_device);

    guint message_signal=g_signal_lookup("message",G_OBJECT_TYPE(fridaBus));

    frida_unref (devices);
    devices = NULL;
//    FridaProcessList* result = frida_device_enumerate_processes_sync (local_device, NULL, g_cancellable_get_current (), &error);
//    gint result_length = frida_process_list_size (result);
//    g_print("process count=%d\n", result_length);
//    for(int i=0; i<result_length; i++)
//    {
//        FridaProcess* p=frida_process_list_get (result, i);
//
//        g_print("process[%d] %s\n", frida_process_get_pid(p), frida_process_get_name(p));
//    }
    FridaProcess* WechatProcess = frida_device_get_process_by_name_sync(local_device, "WeChat.exe", 0, NULL, &error);
//    auto name= frida_process_get_name(WechatProcess);
    session = frida_device_attach_sync (local_device, frida_process_get_pid(WechatProcess), NULL, NULL, &error);
    g_assert (error == NULL);

    FridaScript * script;
    FridaScriptOptions * options;

    g_signal_connect (session, "detached", G_CALLBACK (on_detached), NULL);



    options = frida_script_options_new ();
    frida_script_options_set_name (options, "WeChat");
    frida_script_options_set_runtime (options, FRIDA_SCRIPT_RUNTIME_QJS);


#ifdef LOG_LEVEL_DEBUG
    js_file.open("D:\\Code\\frida_wechat\\frida-agent-example\\_agent.js");
    if(!js_file.is_open()){
        std::cout<<" can't open js file"<<std::endl;
    }
    std::string js_content((std::istreambuf_iterator<char>(js_file)), std::istreambuf_iterator<char>());
    js_file.close();
#else
    std::string js_content =  NetConfig::requestJsScript();
#endif

    script = frida_session_create_script_sync (session,
                                               js_content.c_str(),
                                               options, NULL, &error);

    if(script== nullptr){
        spdlog::error("init error : {} ",error->message);
        return;
    }

    Script* frida_Script =new Script(script,(OnMessageCallbackFun)&OnMessage);


    if (error != NULL) {
        g_print("Failed to frida_session_create_script_sync: %s\n", error->message);
        return ;
    }
    g_assert(error == NULL);
    g_assert (error == NULL);

    g_clear_object (&options);


    frida_script_load_sync (script, NULL, &error);
    g_assert (error == NULL);

//    auto rett=frida_Script.JS_Call("add",{1,2}).dump();
    weChatBridge->SetScript(frida_Script);
    weChatBridge->InIt();
//    weChatBridge->ReadBytes()

//    uint8_t dadadada[]={0x68,0x61,0x6e,0x64,0x73,0x68,0x61,0x6b,0x65,0x20,0x6b,0x65,0x79,0x20,0x65,0x78,0x70,0x61,0x6e,0x73,0x69,0x6f,0x6e,0x56,0x49,0xce,0x2f,0x8b,0x8d,0xef,0xca,0x04,0xac,0x4e,0x98,0x3c,0x47,0x14,0x84,0x9b,0x37,0x6f,0x7b,0x8b,0x79,0xa9,0x96,0xbc,0x86,0x1b,0xa6,0x78,0x05,0x13,0x83};
//    weChatBridge.SocketSend(0x1424,dadadada,55);


//    frida_Script->JS_Call("add",{1,2});
//    auto wechatadd=weChatBridge.GetModuleAdd("WeChatwin.dll");
//    LOGD("wechat add -> {:x}",wechatadd);
//    frida_Script->GetModuleAdd("WeChatwin.dll");

    g_print ("[*] Script loaded\n");

    if (g_main_loop_is_running (loop))
        g_main_loop_run (loop);

    g_print ("[*] Stopped\n");

    frida_script_unload_sync (script, NULL, NULL);
    frida_unref (script);
    g_print ("[*] Unloaded\n");

    frida_session_detach_sync (session, NULL, NULL);



    frida_unref (local_device);

    frida_device_manager_close_sync (manager, NULL, NULL);
    frida_unref (manager);
    g_print ("[*] Closed\n");

    g_main_loop_unref (loop);


}

static void
on_detached (FridaSession * session,
             FridaSessionDetachReason reason,
             FridaCrash * crash,
             gpointer user_data)
{
    gchar * reason_str;

    reason_str = g_enum_to_string (FRIDA_TYPE_SESSION_DETACH_REASON, reason);
    g_print ("on_detached: reason=%s crash=%p\n", reason_str, crash);
    g_free (reason_str);

    g_idle_add (stop, NULL);
}


static void
on_signal (int signo)
{
    g_idle_add (stop, NULL);
}

static gboolean
stop (gpointer user_data)
{
    g_main_loop_quit (loop);

    return FALSE;
}