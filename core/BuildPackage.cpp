//
// Created by 28264 on 2023/5/22.
//
#include "BuildPackage.h"

#include "../crypto/CryptoTools.h"
#include "../common/Utils.h"
#include "zlib.h"
#include "../crypto/AES_GCM.h"
#include "../we_chat/WXLongLinkMessage.h"
#include "../common/ProtobufHelper.h"
#include "../we_chat/WXCGIUrl.h"
#include <WinSock2.h>



std::string Header::toString(){
#ifdef LOG_LEVEL_DEBUG
    return  std::format(R"(
        plaformSign          :{:X}
            ziped            :{:X}  (1 压缩 2 未压缩)
           algorithm         :{:X}
           cookieLen         :{:X}
           WeChatVersion     :{:X}
           uin_8             :{:X}
           cookie            :{}
           cgi_27            :{:X}
           pb_compress_len:0x{:X}
           pb_compressed_len:0x{:X}
           const_37          :{:X}
           const_39          :{:X}
           isCrc_41          :{:X}
           crc_42            :{:X}
           const_46          :{:X}
           RQT_47            :{:X}
)",
                        plaformSign_0,
                        ziped_1,
                        algorithm_2,
                        cookieLen_3,
                        WeChatVersion_4,
                        uin_8,
                        Utils::byte2string(cookie_12,sizeof(cookie_12)),
                        cgi_27,
                        pb_compress_len_29,
                        pb_compressed_len_33,
                        const_37,
                        const_39,
                        isCrc_41,
                        crc_42,
                        const_46,
                        RQT_47);
#else
    return "";
#endif
};


int __cdecl CRC32_20450B0(unsigned int a1, unsigned __int8* data, unsigned int data_len)
{
    unsigned int v3; // ebx
    unsigned int A; // ecx
    unsigned int B; // edi
    unsigned int v6; // eax
    int v7; // edx
    int v8; // ecx
    unsigned __int8* v10; // esi
    int v11; // eax
    unsigned int v12; // esi
    int v13; // edx
    unsigned int v14; // ecx
    unsigned int v15; // edi
    unsigned int v16; // ecx
    unsigned int v17; // edi
    unsigned int v18; // ecx
    unsigned int v19; // edi
    unsigned int v20; // ecx
    unsigned int v21; // edi
    unsigned int v22; // ecx
    unsigned int v23; // edi
    unsigned int v24; // ecx
    unsigned int v25; // edi
    unsigned int v26; // ecx
    unsigned int v27; // edi
    unsigned int v28; // ecx
    unsigned int v29; // edi
    unsigned int v30; // ecx
    int v31; // edi
    int v32; // ecx
    int v33; // edi
    int v34; // ecx
    int v35; // edi
    int v36; // ecx
    int v37; // edi
    int v38; // ecx
    int v39; // edi
    int v40; // ecx
    int v41; // edi
    int v42; // ecx
    int v43; // eax
    int v44; // edi
    unsigned int v45; // edx
    unsigned int v46; // ecx
    unsigned int v47; // edi
    unsigned int v48; // ecx
    unsigned int v49; // edi
    unsigned int v50; // ecx
    unsigned int v51; // edi
    unsigned int v52; // ecx
    unsigned int v53; // edi
    unsigned int v54; // ecx
    unsigned int v55; // edi
    unsigned int v56; // ecx
    unsigned int v57; // edi
    unsigned int v58; // ecx
    unsigned int v59; // edi
    unsigned int v60; // ecx
    unsigned int v61; // edi
    unsigned int v62; // ecx
    int v63; // edi
    int v64; // ecx
    int v65; // edi
    int v66; // ecx
    int v67; // edi
    int v68; // ecx
    int v69; // edi
    int v70; // ecx
    int v71; // edi
    int v72; // ecx
    int v73; // edi
    int v74; // ecx
    int v75; // eax
    int v76; // edi
    int v77; // eax
    unsigned int v78; // [esp+10h] [ebp+8h]

    v3 = data_len;
    A = (unsigned __int16)a1;                     // 初始化A值为16位的a1的低16位
    B = HIWORD(a1);                               // 初始化B值为16位的a1的高16位
    if (data_len == 1)
    {
        v6 = (unsigned __int16)a1 + *data;
        v7 = v6 - 65521;
        if (v6 < 0xFFF1)
            v7 = (unsigned __int16)a1 + *data;
        v8 = v7 + B - 65521;
        if (v7 + B < 0xFFF1)
            v8 = v7 + B;
        return v7 | (v8 << 16);
    }
    v10 = data;
    if (!data)
        return 1;
    if (data_len >= 0x10)
    {
        if (data_len >= 0x15B0)
        {
            v78 = data_len / 0x15B0;
            do
            {
                v3 -= 5552;
                v13 = 347;
                do
                {
                    v14 = *v10 + A;
                    v15 = v14 + B;
                    v16 = v10[1] + v14;
                    v17 = v16 + v15;
                    v18 = v10[2] + v16;
                    v19 = v18 + v17;
                    v20 = v10[3] + v18;
                    v21 = v20 + v19;
                    v22 = v10[4] + v20;
                    v23 = v22 + v21;
                    v24 = v10[5] + v22;
                    v25 = v24 + v23;
                    v26 = v10[6] + v24;
                    v27 = v26 + v25;
                    v28 = v10[7] + v26;
                    v29 = v28 + v27;
                    v30 = v10[8] + v28;
                    v31 = v30 + v29;
                    v32 = v10[9] + v30;
                    v33 = v32 + v31;
                    v34 = v10[10] + v32;
                    v35 = v34 + v33;
                    v36 = v10[11] + v34;
                    v37 = v36 + v35;
                    v38 = v10[12] + v36;
                    v39 = v38 + v37;
                    v40 = v10[13] + v38;
                    v41 = v40 + v39;
                    v42 = v10[14] + v40;
                    v43 = v10[15];
                    v44 = v42 + v41;
                    v10 += 16;
                    A = v43 + v42;
                    B = A + v44;
                    --v13;
                } while (v13);
                A %= 0xFFF1u;
                B %= 0xFFF1u;
                --v78;
            } while (v78);
            if (!v3)
                return A | (B << 16);
            if (v3 < 0x10)
                goto LABEL_30;
        }
        v45 = v3 >> 4;
        do
        {
            v3 -= 16;
            v46 = *v10 + A;
            v47 = v46 + B;
            v48 = v10[1] + v46;
            v49 = v48 + v47;
            v50 = v10[2] + v48;
            v51 = v50 + v49;
            v52 = v10[3] + v50;
            v53 = v52 + v51;
            v54 = v10[4] + v52;
            v55 = v54 + v53;
            v56 = v10[5] + v54;
            v57 = v56 + v55;
            v58 = v10[6] + v56;
            v59 = v58 + v57;
            v60 = v10[7] + v58;
            v61 = v60 + v59;
            v62 = v10[8] + v60;
            v63 = v62 + v61;
            v64 = v10[9] + v62;
            v65 = v64 + v63;
            v66 = v10[10] + v64;
            v67 = v66 + v65;
            v68 = v10[11] + v66;
            v69 = v68 + v67;
            v70 = v10[12] + v68;
            v71 = v70 + v69;
            v72 = v10[13] + v70;
            v73 = v72 + v71;
            v74 = v10[14] + v72;
            v75 = v10[15];
            v76 = v74 + v73;
            v10 += 16;
            A = v75 + v74;
            B = A + v76;
            --v45;
        } while (v45);
        if (v3)
        {
            LABEL_30:
            do
            {
                v77 = *v10++;
                A += v77;
                B += A;
                --v3;
            } while (v3);
        }
        A %= 0xFFF1u;
        B %= 0xFFF1u;
        return A | (B << 16);
    }
    if (data_len)
    {
        do
        {
            v11 = *v10++;
            A += v11;
            B += A;
            --v3;
        } while (v3);
    }
    v12 = A - 65521;
    if (A < 0xFFF1)
        v12 = A;
    return v12 | ((B + 15 * (B / 0xFFF1)) << 16);
}





string Dword2String(DWORD dw)
{
    DWORD dwData = dw;
    DWORD dwData2 = 0x80 * 0x80 * 0x80 * 0x80;
    int nLen = 4;
    uint8_t hex[5] = { 0 };
    DWORD dwOutLen = 0;

    while (nLen > 0)
    {
        if (dwData > dwData2)
        {
            hex[nLen] = dwData / dwData2;
            dwData = dwData % dwData2;
            dwOutLen++;
        }

        dwData2 /= 0x80;
        nLen--;
    }

    hex[0] = dwData;
    dwOutLen++;

    for (int i = 0; i < (int)(dwOutLen - 1); i++)
    {
        hex[i] += 0x80;
    }

    return string((const char*)hex, dwOutLen);
}

DWORD String2Dword(string str, DWORD &dwOutLen)
{
    DWORD dwLen = str.size();

    if (!dwLen)	return 0;


    DWORD dwRet = 0;
    DWORD dwTemp = 1;
    int nLen = 0;
    while (nLen < 5 && nLen<dwLen)
    {
        unsigned char c = (unsigned char)str[nLen];

        if (!(c >> 7))
        {
            dwRet += c * dwTemp;
            nLen++;
            break;
        }
        else
        {
            dwRet += (c & 0x7f) * dwTemp;
            dwTemp *= 0x80;
            nLen++;
        }
    }

    dwOutLen = nLen;

    return dwRet;
}
string MakeHeader(Header& header, bb::ByteBuffer& byteBuff)
{
    string strHeader;
    //添加固定标识
    byteBuff.putChar(0xBF);

    ////是否使用压缩算法(最后2bits)(1表示使用zlib压缩)(压缩后长度可能变长,不一定使用压缩算法)
    unsigned char SecondByte = (header.pb_compress_len_29 == header.pb_compressed_len_33) ? 0x2 : 0x1;

    ////包头长度最后写入
    byteBuff.putChar(SecondByte);

    //加密算法(前4bits),默认使用aes加密(5),需要rsa加密的CGI重载此虚函数
    unsigned char ThirdByte = 0x5 << 4;

    //cookie长度(后4bits)，当前协议默认15位
    ThirdByte += 0xf;

    byteBuff.putChar(ThirdByte);

    ////写入版本号(大端4字节整数)
    DWORD dwVer = htonl(header.WeChatVersion_4);
    byteBuff.putBytes((uint8_t*)&dwVer, 4);

    //写入uin(大端4字节整数)
    DWORD dwUin = htonl(header.uin_8);
    byteBuff.putBytes((uint8_t*)&dwUin, 4);

    //写入cookie
    std::string cookie((char*)header.cookie_12,15);
    byteBuff.putBytes((uint8_t*)&header.cookie_12, 15);

    //cgi type(变长整数)
    string strCgi = Dword2String(header.cgi_27);
    byteBuff.putBytes((uint8_t*)(strCgi.data()), strCgi.size());

    //protobuf长度(变长整数)
    string strProtobuf = Dword2String(header.pb_compress_len_29);
    byteBuff.putBytes((uint8_t*)(strProtobuf.data()), strProtobuf.size());

    //protobuf压缩后长度(变长整数)
    string strCompressed = Dword2String(header.pb_compressed_len_33);
    byteBuff.putBytes((uint8_t*)(strCompressed.data()), strCompressed.size());

    //常数
    string const_37 = Dword2String(header.const_37);
    byteBuff.putBytes((uint8_t*)(const_37.data()), const_37.size());

    string const_39 = Dword2String(header.const_39);
    byteBuff.putBytes((uint8_t*)(const_39.data()), const_39.size());

    //CRC
    string CRC = Dword2String(header.crc_42);
    byteBuff.putBytes((uint8_t*)(CRC.data()), CRC.size());

    byteBuff.putChar(header.const_46);


    string RQT_47 = Dword2String(header.RQT_47);
    byteBuff.putBytes((uint8_t*)(RQT_47.data()), RQT_47.size());

    byteBuff.putChar(0x0);
    byteBuff.putChar(0x0);
    byteBuff.putChar(0x0);

    //将包头长度写入第二字节前6bits(包头长度不会超出6bits)
    auto NewSecondByte = byteBuff.getChar(1);
    NewSecondByte += (byteBuff.size() << 2);
    //将正确的第二字节写入包头
    byteBuff.replace(SecondByte, NewSecondByte, 1, true);


    return strHeader;

}

/*
直接收到文字消息
 ByteArray({   A1>>2= 0x28
               #-------------#-------------#-------------#-------------#
               | 00 01 02 03 | 04 05 06 07 | 08 09 0A 0B | 0C 0D 0E 0F |
               #-------------#-------------#-------------#-------------#
    0x00000000 | BF A1 5F 00 | 00 00 00 A9 | AA F6 4B 67 | 43 08 0F 00 | .._.......KgC...
    0x00000010 | 00 00 00 15 | 08 4A 79 78 | B5 00 8A 01 | F9 05 8B 04 | .....Jyx........
    0x00000020 | 00 00 00 FF | 00 00 00 00 | 46 28 2A DC | D9 90 C7 40 | ........F(*....@
    0x00000030 | 0F 9A 30 AC | 88 EE 91 73 | C0 DE 1B D9 | E7 42 B3 11 | ..0....s.....B..
    0x00000040 | 2C A2 AA 6C | 59 25 37 3D | DD F4 AF 8B | 12 3F 9B 73 | ,..lY%7=.....?.s

 自己构造 发出消息后的 返回的响应包
 ByteArray({
               #-------------#-------------#-------------#-------------#
               | 00 01 02 03 | 04 05 06 07 | 08 09 0A 0B | 0C 0D 0E 0F |
               #-------------#-------------#-------------#-------------#
    0x00000000 | 00 00 00 2F | 00 10 00 01 | 3B 9A CA ED | 00 00 00 60 | .../....;......`
    0x00000010 | 7E 0F FF FF | FF F3 00 00 | 00 00 DB 43 | 08 0F 00 00 | ~..........C....
    0x00000020 | 00 00 20 AD | 23 95 DF 1D | 00 8A 04 00 | 00 00 00    | .. .#..........
               #-------------#-------------#-------------#-------------#
}, Length: 0x2f, Capacity: 0x1000)
*/
/// 解析包 原始包
/// \param header
/// \param byteBuff
/// \return
bool UnPackHeader(Header& header, bb::ByteBuffer& byteBuff,uint32_t& HeadLen,bool is_request=false)
{


    if(byteBuff.size()<=0)
        return false;
    uint8_t platform=byteBuff.getChar();  //平台标识
    if(platform!=0xbf){
        return false;
    }
    header.plaformSign_0=platform;

    uint8_t HeadLenWigthFlag=byteBuff.getChar();
    //解析包头长度(前6bits)
//    uint32_t HeadLen=HeadLenWigthFlag>>2;
    HeadLen=HeadLenWigthFlag>>2;
    if(HeadLen<0x10){
        spdlog::error("HeadLen<0x10");
        return false;
    }

    bool is_compress=(1 == (HeadLenWigthFlag & 0x3)) ? true :false ;//1压缩 2未压缩
    header.ziped_1=is_compress;

    //加密算法(前4bits),默认使用aes加密(5),需要rsa加密的CGI重载此虚函数
    unsigned char ThirdByte = byteBuff.getChar() ;


    uint32_t Algorithm =ThirdByte>>4;//解密算法(前4 bits)(05:aes / 07:rsa)(仅握手阶段的发包使用rsa公钥加密,由于没有私钥收包一律aes解密)
    header.algorithm_2=Algorithm;

    uint32_t cookie_len=ThirdByte&0x0f;  //获取低四位  //cookie长度(后4 bits)
    header.cookieLen_3=cookie_len;

    uint32_t  version=byteBuff.getInt();	//服务器版本,无视(4字节)
    header.WeChatVersion_4=version;

    uint32_t uin=byteBuff.getIntBE();
    header.uin_8=uin;

    if (cookie_len && cookie_len <= 0xf)       //刷新cookie(超过15字节说明协议头已更新)
    {
//        byteBuff.getBytes(cookie, cookie_len);
        byteBuff.getBytes(header.cookie_12, cookie_len);

    } else{
        spdlog::error("rect data cookie len error");
        return false;
//        throw "rect data cookie len error";
    }

    uint8_t tmp_buff[0x5]={0};
    DWORD tmp_len=0;   //读取字节长度
    //cgi type,变长整数,无视
    byteBuff.getBytes(tmp_buff,0x5);
    uint32_t cgi_type=String2Dword(string((char*)&tmp_buff),tmp_len);
    byteBuff.setReadPos(byteBuff.getReadPos()-5+tmp_len);
    header.cgi_27=cgi_type;

    tmp_len=0;
    memset(tmp_buff,0x0, sizeof(tmp_buff));
    byteBuff.getBytes(tmp_buff,0x5);
    uint32_t bp_len=String2Dword(string((char*)&tmp_buff),tmp_len);  //解压后PB长度
    byteBuff.setReadPos(byteBuff.getReadPos()-5+tmp_len);
    header.pb_compress_len_29=bp_len;

    //protobuf压缩后长度(变长整数)
    tmp_len=0;
    memset(tmp_buff,0x0, sizeof(tmp_buff));
    byteBuff.getBytes(tmp_buff,0x5);
    uint32_t bp_len_compress=String2Dword(string((char*)&tmp_buff),tmp_len);  //压缩后PB长度
    byteBuff.setReadPos(byteBuff.getReadPos()-5+tmp_len);
    header.pb_compressed_len_33=bp_len_compress;


    if(!is_request){  //是请求的就到这里返回了
        return true;
    }

    tmp_len=0;
    memset(tmp_buff,0x0, sizeof(tmp_buff));
    byteBuff.getBytes(tmp_buff,0x5);
    header.const_37=String2Dword(string((char*)&tmp_buff),tmp_len);
    byteBuff.setReadPos(byteBuff.getReadPos()-5+tmp_len+1);//读出来0 得加1

    tmp_len=0;
    memset(tmp_buff,0x0, sizeof(tmp_buff));
    byteBuff.getBytes(tmp_buff,0x5);
    header.const_39=String2Dword(string((char*)&tmp_buff),tmp_len);
    byteBuff.setReadPos(byteBuff.getReadPos()-5+tmp_len);

    tmp_len=0;
    memset(tmp_buff,0x0, sizeof(tmp_buff));
    byteBuff.getBytes(tmp_buff,0x5);
    header.crc_42=String2Dword(string((char*)&tmp_buff),tmp_len);
    byteBuff.setReadPos(byteBuff.getReadPos()-5+tmp_len);

    byteBuff.getBytes(&header.const_46,1);

    tmp_len=0;
    memset(tmp_buff,0x0, sizeof(tmp_buff));
    byteBuff.getBytes(tmp_buff,0x5);
    header.RQT_47=String2Dword(string((char*)&tmp_buff),tmp_len);
    byteBuff.setReadPos(byteBuff.getReadPos()-5+tmp_len);

    return true;
}

BuildPackage::BuildPackage(WeChatBridge *weChatBridge) {
    this->weChatBridge=weChatBridge;

}
/// 构建内层包
/// \param HeadByteBuff  返回组装的内部包头 0xbf 开头那个
/// \param pb_data
/// \param pb_len
void BuildPackage::ConstructInnerPackage(bb::ByteBuffer& HeadByteBuff,std::vector<uint8_t>& pb_data,uint32_t pb_len,std::uint16_t cmdId) {
//    bb::ByteBuffer HeadByteBuff(0x200);
    bb::ByteBuffer BodyByteBuff(0x200);
    //00 00 00 7e   00 10 00 01   00 00 00 ed   00 00 02 91 bf ba
    struct Header reqHead = {
            .plaformSign_0 = 0x0,
            .ziped_1 = 2,
            .algorithm_2 = 0x5,
            .cookieLen_3 = 0xf,
            .WeChatVersion_4 = 0x63090217,
            .uin_8 = 0x0,
            .cookie_12 = 0x0,
//            .cgi_27 = 522,  //发消息
            .cgi_27 = cmdId,  //发消息
            .pb_compress_len_29 = 0x0,
            .pb_compressed_len_33 = 0x0,
            .const_37 = 0x0,
            .const_39 = 0xf,
            .isCrc_41 = 0x1,
            .crc_42 = 0x0,
            .const_46 = 0x0,
            .RQT_47 = 0x0,
    };
//    uint8_t pb_data[] = {
//
//            0x08,0x01,0x12,0x2d,0x0a,0x15,0x0a,0x13,0x77,0x78,0x69,0x64,0x5f,0x34,0x7a,0x72,0x36,0x31,0x36,0x69,0x72,0x36,0x66,0x69,0x31,0x32,0x32,0x12,0x06,0x31,0x32,0x31,0x32,0x31,0x32,0x18,0x01,0x20,0xdb,0xca,0x8d,0xa3,0x06,0x28,0xdb,0xca,0x8d,0xa3,0x06
//
//    };

//    uint32_t pb_len=0;

//    shared_ptr<uint8_t[]> pb_data = ProtobufHelper::newMsg(pb_len);
    //08 01 12 60 0A 15 0A 13 77 78 69 64 5F 34 7A 72 36 31 36 69 72 36 66 69 31 32 32 12 06 31 32 33 31 32 33 18 01 20 DB B1 BC 43 28 8D DA AD A4 01 32 32 3C 6D 73 67 73 6F 75 72 63 65 3E 3C 61 6C 6E 6F 64 65 3E 3C 63 66 3E 32 3C 2F 63 66 3E 3C 2F 61 6C 6E 6F 64 65 3E 3C 2F 6D 73 67 73 6F 75 72 63 65 3E
//    uint32_t pb_len = sizeof(pb_data);
    reqHead.pb_compressed_len_33 = pb_len;
    reqHead.pb_compress_len_29 = pb_len;
//    reqHead.uin_8 = WeChatBridge::G_UIN;
    reqHead.uin_8 = weChatBridge->G_UIN;
    memmove(reqHead.cookie_12, (void*)&weChatBridge->G_Cookie, sizeof(weChatBridge->G_Cookie));



//    uint32_t uin = htonl(WeChatBridge::G_UIN);
    uint32_t uin = htonl(weChatBridge->G_UIN);
    uint32_t _pb_len = htonl(pb_len);

    uint8_t v10[0x10 + 0x10 + 0x4];
    uint8_t md5_outBuf[0x30] = { 0 };

    memset(md5_outBuf, 0x0, sizeof(v10));
    memmove(v10, (void*)&uin, 4);

    memmove(v10 + 4,weChatBridge->G_ECDH_Key, sizeof(weChatBridge->G_ECDH_Key));
    CryptoTools::MD5(v10, 20, md5_outBuf);                                        //第一次md5

    memset(v10, 0x0, sizeof(v10));
    memmove(v10, (void*)&_pb_len, 4);
    memmove(v10 + 4, weChatBridge->G_ECDH_Key, sizeof(weChatBridge->G_ECDH_Key));
    memmove(v10 + 4 + sizeof(weChatBridge->G_ECDH_Key), md5_outBuf, 0x10);

    memset(md5_outBuf, 0x0, sizeof(md5_outBuf));
    CryptoTools::MD5(v10, sizeof(v10), md5_outBuf);                              //第二次md5

    auto tmp_1 = CRC32_20450B0(0, 0, 0);
    auto tmp_2 = CRC32_20450B0(tmp_1, md5_outBuf, 0x10);
    uint32_t crc_ret = CRC32_20450B0(tmp_2, pb_data.data(), pb_len);
    reqHead.crc_42 = crc_ret;                                       //设置CRC
    //reqHead.RQT_47 = 0x216A580E;
    reqHead.RQT_47 = 0x0;

    MakeHeader(reqHead, HeadByteBuff);
//    cout << "压缩后包头 " << endl;
//    cout << HeadByteBuff << endl;
    uint8_t* AES_RET= nullptr;
    uint32_t enc_data_len = 0;
    if (reqHead.ziped_1 == 1) {  //使用压缩
        uLongf compressedLen = compressBound(pb_len);                  //压缩后的长度
        uint8_t* compressedData = new uint8_t[compressedLen + 1];
        memset(compressedData, 0x0, compressedLen + 1);
        auto err = compress(compressedData, &compressedLen, pb_data.data(), pb_len);
        reqHead.pb_compressed_len_33 = compressedLen;
        //加密
        uint8_t* enc_data = new uint8_t[compressedLen + 16];
        memset(enc_data, 0x0, compressedLen + 16);
        enc_data_len = CryptoTools::Enc_AES_CBC(compressedData, compressedLen, weChatBridge->G_AES_Key,  weChatBridge->G_AES_Key, enc_data);
        AES_RET=enc_data;
    }
    else {
        uint8_t* enc_data = new uint8_t[pb_len + 16];
        memset(enc_data, 0x0, pb_len + 16);
        enc_data_len = CryptoTools::Enc_AES_CBC(pb_data.data(), pb_len,weChatBridge->G_AES_Key,  weChatBridge->G_AES_Key, enc_data);
        AES_RET = enc_data;
    }
    BodyByteBuff.putBytes(AES_RET, enc_data_len);
//    cout << "加密后包体 " << endl;
//    Utils::print_hex(AES_RET,enc_data_len);
    delete[] AES_RET;


//    cout << "合并 " << endl;
    HeadByteBuff.put(&BodyByteBuff);
//    std::cout << HeadByteBuff << std::endl;
//    cout << "合并包体hex " << endl;
//    HeadByteBuff.printHex();


}

/*
 * HeadByteBuff 是 内部BF 开头的 数据
 * 头上凭借四字节PacketLength ProtocalVersion cmadid Seq
 *
 * 发消息 requestID = 237
 * */
void BuildPackage::ConstructTlsPackage(bb::ByteBuffer& HeadByteBuff,uint32_t RandomSeq,bb::ByteBuffer& OutBuff,std::uint16_t cmdID) {
//    bb::ByteBuffer bodyTest(0x200);
//    bb::ByteBuffer OutbodyTest(0x200);
//    uint8_t payload[]={
//            0xbf,0xba,0x5f,0x63,0x09,0x02,0x17,0xa9,0xaa,0xf6,0x4b,0x5d,0x43,0x08,0x0f,0x00,0x00,0x00,0x00,0x40,0x01,0xfe,0x0a,0x95,0x25,0x00,0x8a,0x04,0x2e,0x2e,0x00,0x0f,0x8a,0xad,0x8c,0xdb,0x0d,0x00,0x86,0xc0,0xd0,0x89,0x02,0x00,0x00,0x00,0xc6,0xa8,0x74,0x57,0x8c,0xc3,0xa9,0x7f,0x9d,0x5d,0x52,0x31,0x77,0xc8,0x86,0x43,0x75,0xb0,0xfa,0x55,0x59,0x5c,0x04,0xf4,0x42,0x84,0x13,0xee,0x2d,0x37,0x22,0x94,0xff,0x11,0x43,0x4f,0x31,0xea,0xf2,0xdd,0xb7,0x84,0x08,0xcc,0x1a,0xd5,0x2d,0xbe
//    };
//    bodyTest.putBytes(payload, sizeof(payload));
    WXLongLinkMessage wxLongLinkMessage(RandomSeq,cmdID2ReqId[cmdID],HeadByteBuff);
//    WXLongLinkMessage wxLongLinkMessage(0x60,237,bodyTest);
    bb::ByteBuffer LongLinkMessage=wxLongLinkMessage.ToByteArray();
//    std::cout<<LongLinkMessage<<std::endl;
    weChatBridge->LongLinkPack(LongLinkMessage,OutBuff);
//    std::cout<<OutBuff<<std::endl;

    //发送包
//    uint8_t* send_buf = new uint8_t[OutBuff.size()];
//    OutBuff.getBytes(send_buf,OutBuff.size());
//    weChatBridge->SocketSend(std::stoi(weChatBridge->LonglinkHand, nullptr,16),send_buf,OutBuff.size());
//    delete[] send_buf;
}

//    out_data.getBytes(enc_data,Response.pb_compressed_len_33);
//dec_data+16*18
//    auto dec_data_len = CryptoTools::Dec_AES_CBC(enc_data, Response.pb_compressed_len_33,aes_key, aes_key, dec_data);
//    auto dec_data_len = CryptoTools::Dec_AES_CBC(enc_data, remain_length,aes_key, aes_key, dec_data);
//    int dec_data_len=0x0;
//    if(Response.algorithm_2==0x5){
//        dec_data_len = CryptoTools::Dec_AES_CBC(enc_data, remain_length,weChatBridge->G_AES_Key, weChatBridge->G_AES_Key, dec_data);
//
//    }

uint32_t BuildPackage::DecryptBody(struct Header& Response,uint8_t* enc_data,uint32_t remain_length,uint8_t*dec_data){
    if(Response.algorithm_2==0x5){

        uint32_t ret_len=CryptoTools::Dec_AES_CBC(enc_data, remain_length,weChatBridge->G_AES_Key, weChatBridge->G_AES_Key, dec_data);
        MMTLSLOG(R"(
AES CBC 解密
key      : {}
iv       : {}
解密前数据 :
{}
解密后数据 :
{}
)", Utils::byte2string(weChatBridge->G_AES_Key,sizeof(weChatBridge->G_AES_Key)),
    Utils::byte2string(weChatBridge->G_AES_Key,sizeof(weChatBridge->G_AES_Key)),
    Utils::byte2string(enc_data,remain_length),
    Utils::byte2string(dec_data,ret_len));
        //返回解析后的长度
        return ret_len;

    }else{
        spdlog::error("unhandle decrypt method");
        return 0;
    }
}
//    uint32_t un_comress_data_len=Response.pb_compress_len_29+0x10;
//
//    uint8_t* un_compress_data = new uint8_t[un_comress_data_len];
//
//    uncompress(un_compress_data,(uLongf*)&un_comress_data_len,dec_data,dec_data_len);
//    if(un_comress_data_len!=Response.pb_compress_len_29){
//        throw "decompress parse return fail";
//    }
//    OutBuff.putBytes(un_compress_data,un_comress_data_len);
void BuildPackage::DeCompressBody(struct Header& Response,uint8_t* dec_data,uint32_t dec_data_len,bb::ByteBuffer& OutBuff){

    uint32_t un_comress_data_len=Response.pb_compress_len_29+0x10;

    uint8_t* un_compress_data = new uint8_t[un_comress_data_len];

    uncompress(un_compress_data,(uLongf*)&un_comress_data_len,dec_data,dec_data_len);
    MMTLSLOG(R"(   Decompress
        解压缩之 前 数据 : {}
        解压缩之 前 长度 : {}
        解压缩之 后 数据 : {}
        解压缩之 后 长度 : {}
)",Utils::byte2string(dec_data,dec_data_len),dec_data_len,
         Utils::byte2string(un_compress_data,un_comress_data_len),un_comress_data_len);
    if(un_comress_data_len!=Response.pb_compress_len_29){
        //TODO 解压缩失败
        OutBuff.clear();
        spdlog::error("DeCompressBody error ");
        delete[] un_compress_data;
        return;
    }
    OutBuff.putBytes(un_compress_data,un_comress_data_len);
    delete[] un_compress_data;
}

/// 00 00 02 38 00 10 00 01 3B 9A CA 79 00 00 00 68   0x10的头
/// BF A1 5F 00 00 00 00 A9 AA F6 4B EA 43 08 0F 00
/// 00 00 00 4F 8B 9F E8 E5 4A 00 8A 01 CF 05 F4 03
/// 00 00 00 FF 00 00 00 00   A4 96 41 6F A6 43 31 75  这后面的都是AES CBC加密后的包体
///
/// \param out_data  输入数据
/// \param Response
/// \param OutBuff   返回值
/// \param is_request
/// \return
bool BuildPackage::UnpackPackage(std::unique_ptr<bb::ByteBuffer>& out_data,struct Header& Response,bb::ByteBuffer& OutBuff,bool is_request) {
//
//    WXLongLinkMessage Message(HeadByteBuff);
//
//    //cgi-bin/micromsg-bin/newsendmsg RequestID = 237, ResponseID = 1000000237)
//    if(Cgi_List.find(Message.GetGenericCmd()) == Cgi_List.end()){
//        OutBuff.clear();
//        OutBuff.resize(0);
//        return std::move(Message);
//    }
//    std::unique_ptr<bb::ByteBuffer> out_data;
//    //解析0x10的头部剩下才是真正的0xbf开头的内部包
//    Message.GetPayload(out_data);
//
//    struct Header Response;
//    if(!Message.GetSeqID()) { //SeqID==0 返回
//        out_data->clear();
//        return std::move(Message);
//    }
//
//    std::unique_ptr<bb::ByteBuffer> out_data;
    //解析0x10的头部剩下才是真正的0xbf开头的内部包
//    Message.GetPayload(out_data);

    uint32_t HeadLen=0x0;
    if(!UnPackHeader(Response,*out_data.get(),HeadLen,is_request)){ //这里开始解包 0xbf开头
        spdlog::error("unpack header error");
//        std::cout<<"error data \r\n"<<HeadByteBuff<<std::endl;
        return false;
    }
#ifdef MMTLS_DEBUG
    spdlog::info("包头长度 : {:x}",HeadLen);
    spdlog::debug("内部包头 {}",Response.toString());
#endif

    if(HeadLen<out_data->size()){  //包头长度小于包长的话直接无视后面数据 解析包体
        out_data->setReadPos(HeadLen);
    }

    auto remain_length = out_data->size()-out_data->getReadPos();//剩余的长度全部都拿去解密

    uint8_t* enc_data = new uint8_t[remain_length+0x10];  //多申请一点防止溢出
//    uint8_t* dec_data = new uint8_t[remain_length+0x10];
    uint8_t* dec_data = new uint8_t[remain_length+0x10];
//    uint8_t aes_key[]= {0x23,0x48,0x47,0x49,0x48,0x64,0x38,0x3f,0x64,0x75,0x4f,0x47,0x42,0x4d,0x4f,0x28};
    memset(enc_data, 0x0, remain_length);
    memset(dec_data, 0x0, remain_length);
//    HeadByteBuff.getBytes(enc_data,Response.pb_compressed_len_33);

    out_data->getBytes(enc_data,remain_length);


    int dec_data_len = DecryptBody(Response,enc_data,remain_length,dec_data);

    //PB长度相等说明未压缩
    if(Response.pb_compress_len_29==Response.pb_compressed_len_33){

        OutBuff.putBytes(dec_data,dec_data_len);

    }else{ //压缩处理代码

        DeCompressBody(Response,dec_data,dec_data_len,OutBuff);
    }

    delete[] enc_data;
    delete[] dec_data;

    return true;

}

bb::ByteBuffer ClinetHello::GetBytes() {
    bb::ByteBuffer buffer;

    buffer.putBytes( (std::uint8_t*)&const_data,
                            sizeof(const_data)
                            +sizeof(client_random)
                            +4+
                            sizeof(const_data2)+
                            sizeof(PSK)
                            );
    return std::move(buffer);
}
