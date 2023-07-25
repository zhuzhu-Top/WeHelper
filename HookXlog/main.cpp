//
// Created by 28264 on 2023/5/30.
//
#include "frida-gum.h"
#include <iostream>
#include <Windows.h>
#include <sstream>
#include <mutex>

std::mutex g_mtx;
using namespace std;

DWORD getWeChatwinADD() {

    HMODULE WinAdd = LoadLibraryW(L"WeChatWin.dll");
    return (DWORD)WinAdd;
}
static char LOG_TXT_BUF[0x5000]={
        0x0
};

static void __stdcall On_LOG(DWORD EBP,DWORD EAX)
{
    std::unique_lock<std::mutex> ulokc(g_mtx);
    EBP-=0x4084;
    if(EAX==0 || (void*)EBP == nullptr){
        return;
    }
//    memcpy(LOG_TXT_BUF,(void*)EBP,EAX);

    OutputDebugString((char*)EBP);

//    memset(LOG_TXT_BUF,0x0,sizeof(LOG_TXT_BUF));
}

void InnerDllMain(){

    HANDLE CurrentProcess=OpenProcess(PROCESS_ALL_ACCESS, NULL, GetCurrentProcessId());
    BYTE NopCode[28] = { 0x90, 0x90,
                         0x90, 0x90,
                         0x90, 0x90,0x90, 0x90,0x90,0x90,
                         0x90, 0x90,0x90, 0x90,0x90,0x90,
                         0x90, 0x90,0x90, 0x90,0x90,0x90,//18
                         0x90, 0x90,
                         0x90,
                         0x90, 0x90,0x90};

    if (WriteProcessMemory(CurrentProcess, (LPVOID)(getWeChatwinADD()+0x203D5E7), NopCode, sizeof(NopCode), NULL) == 0) {
        OutputDebugString("write Wechat Nop error");

    }
    if (WriteProcessMemory(CurrentProcess, (LPVOID)(getWeChatwinADD()+0x2083F28), NopCode,2, NULL) == 0) {
        OutputDebugString("write Wechat Nop error");

    }
    const guint8 kLevelAll[]={0x0,0x0,0x0,0x0};
    gum_memory_write((gpointer)(getWeChatwinADD()+0x2EF0B6C),kLevelAll,4);


    gum_init_embedded();
    auto page_size= gum_query_page_size();
    gpointer jump_code=gum_malloc(page_size);

    stringstream log_txt;
    log_txt<< " code add :  " <<std::hex<<jump_code;

    string str_log=log_txt.str();
    OutputDebugString(str_log.c_str());

    gum_memory_patch_code((gpointer)(getWeChatwinADD()+0x203D5E7),page_size,[] (void* addr, void*) {
        GumX86Writer* writer = gum_x86_writer_new(addr);
        gum_x86_writer_put_pushfx(writer);
        gum_x86_writer_put_pushax(writer);

        gum_x86_writer_put_push_reg(writer,GUM_X86_EAX);
        gum_x86_writer_put_push_reg(writer,GUM_X86_EBP);
        gum_x86_writer_put_call_address(writer,(GumAddress)&On_LOG);



        gum_x86_writer_put_popax(writer);
        gum_x86_writer_put_popfx(writer);
        /* Transform a SVC #0x80 into BL #AABBCC */

    }, nullptr);


    gum_deinit_embedded();

    while (true){


    }
}

BOOL APIENTRY DllMain( HMODULE hModule,DWORD  ul_reason_for_call,LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        {
    //MessageBoxA(NULL, "DLL_PROCESS_ATTACH", NULL, MB_OK);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)InnerDllMain, hModule, 0, NULL);
        }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
    //MessageBox(NULL, L"over", L"over", MB_OK);
    break;
}
return TRUE;
}