//
// Created by 28264 on 2023/6/2.
//
#include "NetMain.h"

#include <winsock2.h>

#include "hv/requests.h"

#include <filesystem>
#include <windows.h>
#include "../common/Utils.h"
#include "../include/SimpleIni.h"

#include "pugxml/pugixml.hpp"
#include <fstream>
#include "zlib.h"
#include "../common/ByteBuffer.hpp"

#include "../crypto/CryptoTools.h"
#include <libhv/include/hv/requests.h>


const std::string NetConfig::long_weixin_qq_com= "long.weixin.qq.com";
const std::string NetConfig::szlong_weixin_qq_com= "szlong.weixin.qq.com";



std::vector<std::string> NetConfig::LongLink_ipv4_address;
std::vector<std::string> NetConfig::LongLink_ipv6_address;


bool NetConfig::IsLongLink(string &IP, uint32_t port) {
    for(auto& item : NetConfig::LongLink_ipv4_address){
        if(item==IP){
            return true;
        }
    }

    for(auto& item : NetConfig::LongLink_ipv6_address){
        if(item==IP){
            return true;
        }
    }

    return false;

}

/*解压*/
int httpgzdecompress(Byte *zdata, uLong nzdata, Byte *data, uLong *ndata)
{
    int err = 0;
    z_stream d_stream = { 0 }; /* decompression stream */
    unsigned char dummy_head[2] = { 0x1F, 0x8B };
    d_stream.zalloc = (alloc_func)0;
    d_stream.zfree = (free_func)0;
    d_stream.opaque = (voidpf)0;
    d_stream.next_in = zdata;
    d_stream.avail_in = 0;
    d_stream.next_out = data;
    if (inflateInit2(&d_stream, -MAX_WBITS) != Z_OK) return -1;
    //if (inflateInit2(&d_stream, 47) != Z_OK) return -1;
    while (d_stream.total_in < nzdata) {
        d_stream.avail_in = d_stream.avail_out = 2048; /* force small buffers */
        if ((err = inflate(&d_stream, Z_NO_FLUSH)) == Z_STREAM_END) break;
        if (err != Z_OK)
        {
            if (err == Z_DATA_ERROR)
            {
                d_stream.next_in = (Bytef*)dummy_head;
                d_stream.avail_in = sizeof(dummy_head);
                if ((err = inflate(&d_stream, Z_NO_FLUSH)) != Z_OK)
                {
                    return -1;
                }
            }
            else return -1;
        }
    }
    *ndata = d_stream.total_out;
    if (inflateEnd(&d_stream) != Z_OK) return -1;

    return 0;
}
bool local_zlib_decompress(const char* compressed_data, size_t compressed_size, char* decompressed_data, size_t decompressed_size) {
    z_stream stream;
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    stream.avail_in = compressed_size;
    stream.next_in = (Bytef*)compressed_data;
    stream.avail_out = decompressed_size;
    stream.next_out = (Bytef*)decompressed_data;
    int ret = inflateInit(&stream);
    if (ret != Z_OK) {
        return false;
    }
    ret = inflate(&stream, Z_FINISH);
    if (ret != Z_STREAM_END) {
        inflateEnd(&stream);
        return false;
    }
    inflateEnd(&stream);
    return true;
}


bool gzipInflate( const std::string& compressedBytes, std::string& uncompressedBytes ) {
    if ( compressedBytes.size() == 0 ) {
        uncompressedBytes = compressedBytes ;
        return true ;
    }

    uncompressedBytes.clear() ;

    unsigned full_length = compressedBytes.size() ;
    unsigned half_length = compressedBytes.size() / 2;

    unsigned uncompLength = full_length ;
    char* uncomp = (char*) calloc( sizeof(char), uncompLength );

    z_stream strm;
    strm.next_in = (Bytef *) compressedBytes.c_str();
    strm.avail_in = compressedBytes.size() ;
    strm.total_out = 0;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;

    bool done = false ;

    if (inflateInit2(&strm, (16+MAX_WBITS)) != Z_OK) {
        free( uncomp );
        return false;
    }

    while (!done) {
        // If our output buffer is too small
        if (strm.total_out >= uncompLength ) {
            // Increase size of output buffer
            char* uncomp2 = (char*) calloc( sizeof(char), uncompLength + half_length );
            memcpy( uncomp2, uncomp, uncompLength );
            uncompLength += half_length ;
            free( uncomp );
            uncomp = uncomp2 ;
        }

        strm.next_out = (Bytef *) (uncomp + strm.total_out);
        strm.avail_out = uncompLength - strm.total_out;

        // Inflate another chunk.
        int err = inflate (&strm, Z_SYNC_FLUSH);
        if (err == Z_STREAM_END) done = true;
        else if (err != Z_OK)  {
            break;
        }
    }

    if (inflateEnd (&strm) != Z_OK) {
        free( uncomp );
        return false;
    }

    for ( size_t i=0; i<strm.total_out; ++i ) {
        uncompressedBytes += uncomp[ i ];
    }
    free( uncomp );
    return true ;
}

std::string
NetConfig::requestJsScript() {


    auto response =  requests::post("http://zhuzhu-biu.fun:88/wx_helper_query_js");
//    std::string resp_body = response->Body();
    std::string enc_data = std::move(response->Body());

//    std::string enc_data;
//    enc_data.resize(resp_body.size()*2+1);
//    uint32_t bytes_size=  Utils::string2byte(resp_body,(std::uint8_t*)enc_data.data());
//    enc_data.resize(bytes_size);


    std::uint8_t key[] = {0xf3,0xb9,0xfa,0x10,0x41,0x83,0xe2,0xb7,0xe5,0x2b,0x2e,0xd2,0x5d,0xc9,0x15,0x1b};

    std::string decrypt_body;
    decrypt_body.resize(enc_data.size());

    auto dec_data_len = CryptoTools::Dec_AES_CBC((unsigned char*)enc_data.data(),enc_data.size(),(unsigned char*)&key,(unsigned char*)&key,(unsigned char*)decrypt_body.c_str());
    decrypt_body.resize(dec_data_len);

    std::string de_compressed_data;
    de_compressed_data.resize(dec_data_len*50);
    uLongf dest_buff_len=de_compressed_data.size();

    uncompress( (Byte*)de_compressed_data.c_str(), &dest_buff_len,(Byte *) decrypt_body.c_str(), decrypt_body.size());

    de_compressed_data.resize(dest_buff_len);
    return std::move(de_compressed_data);
}

void GetDnsServers(){
    http_headers headers;
    headers["Accept-Encoding"] = "gzip, deflate";
    auto resp = requests::get("http://dns.weixin.qq.com/cgi-bin/micromsg-bin/newgetdns",headers);
    if (resp == NULL) {
        spdlog::info("request  newgetdns failed!");
    }
    std::string str_resp= resp->body;
    std::string decompress_data;
    decompress_data.resize(0x6000);
//    Bytef *dest= new uint8_t[0x6000];
    uLong dest_buff_len=0x6000;
    auto error_ret= httpgzdecompress((Byte *) str_resp.c_str(), str_resp.size(), (Byte*)decompress_data.c_str(), &dest_buff_len);
    if (error_ret!=0){
        spdlog::error("unzip response error");
        return;
    }
    pugi::xml_document doc;


    std::ofstream ofs("newgetdns.txt", std::ios::out | std::ios::binary);
    if (ofs.is_open()) {
        ofs.write(decompress_data.c_str(), dest_buff_len);
        ofs.close();
        spdlog::info("write response to file successfully.");
    } else {
        spdlog::error("open file failed.");
    }
    pugi::xml_parse_result result = doc.load_string(decompress_data.c_str());
    // 选取符合条件的节点
    pugi::xpath_query query("/dns/domainlist/domain[@name='extshort.weixin.qq.com']");
//    pugi::xml_node wx_short_node = query.evaluate_node_set(doc)[0].node();

    pugi::xml_node domainlist=  doc.child("dns").child("domainlist");
    for (auto domain = domainlist.first_child();domain;domain=domain.next_sibling() ) {


        if(
                domain.attribute("name").value()==NetConfig::long_weixin_qq_com ||
                domain.attribute("name").value()==NetConfig::szlong_weixin_qq_com
        ){

            for (auto ip : domain) {
                std::string ip_type = ip.name();
                std::string ip_addr = ip.first_child().value();
                if(ip_type=="ipv6"){
                    NetConfig::LongLink_ipv6_address.push_back(ip.first_child().value());
                }else{

                    NetConfig::LongLink_ipv4_address.push_back(ip_addr);
                }
            }
        }
    }
}





//    CSimpleIniA ini;
//    ini.SetUnicode();
//    std::filesystem::path path;
//    PWSTR path_tmp;

//    auto get_folder_path_ret = SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &path_tmp);

    /* Error check */
//    if (get_folder_path_ret != S_OK) {
//        CoTaskMemFree(path_tmp);
//        spdlog::error("get_folder_path_ret != S_OK");
//    }
    /* Convert the Windows path type to a C++ path */
//    path = path_tmp;

    /* Free memory :) */
//    CoTaskMemFree(path_tmp);

//    path+="\\Tencent\\WeChat\\";
//    path+=std::to_string(num);
//    path+="\\host";

//
//    for (const auto& entry : std::filesystem::directory_iterator(path)) {
//        if (entry.is_regular_file() && entry.path().filename().string().find("no_ssid_wifi") == 0) {
////            entry.path().
//            spdlog::info("Found wechat net cash file {}",entry.path().string());
//
//            SI_Error rc = ini.LoadFile(entry.path().c_str());
//            if (rc < 0) {
//                spdlog::info("open {} fail ",entry.path().filename().string());
//                return;
//            };
//            std::string ipv4  = ini.GetValue("szlong.weixin.qq.com", "ip", "");
//            std::string ipv6= ini.GetValue("szlong.weixin.qq.com", "ipv6", "");
//            std::vector<std::string> vec_ipv4;
//            std::vector<std::string> vec_ipv6;
//            if(ipv4.size()>5){
//                Utils::splitString(ipv4,';',vec_ipv4);
//                for (auto& item : vec_ipv4 ){
//                    NetConfig::LongLink_ipv4_address.push_back(item);
//                }
//            }
//            if(ipv6.size()>5){
//                Utils::splitString(ipv6,';',vec_ipv6);
//                for (auto& item : vec_ipv6 ){
//                    NetConfig::LongLink_ipv6_address.push_back(item);
//                }
//            }
//
//
//
//        }
//    }

void NetMain(){
    GetDnsServers();
    // 初始化 Winsock
    WSADATA wsaData;
    int status = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (status != 0) {
        std::cerr << "Failed to initialize Winsock: " << status << std::endl;
        return ;
    }
    NetTools::GetIPAddresses(NetConfig::long_weixin_qq_com,NetConfig::LongLink_ipv4_address,NetConfig::LongLink_ipv6_address);
    if (!(NetConfig::LongLink_ipv4_address.size() >0 || NetConfig::LongLink_ipv6_address.size() > 0) ){
        spdlog::error("not get ipv4 or ipv6 lingling address ");
    }
    spdlog::info(R"(
init Get Lobglink Addr :
            ipv4 : {}
            ipv6 : {}

    )", fmt::format("{}", fmt::join(NetConfig::LongLink_ipv4_address.begin(), NetConfig::LongLink_ipv4_address.end(), " ")),
        fmt::format("{}", fmt::join(NetConfig::LongLink_ipv6_address.begin(), NetConfig::LongLink_ipv6_address.end(), " "))
    );
    // 清理 Winsock
    WSACleanup();
}