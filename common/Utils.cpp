//
// Created by 28264 on 2023/5/27.
//

#include "Utils.h"
#include <fstream>
#include "openssl/md5.h"
#include "openssl/sha.h"
#include <chrono>
#include <openssl/core_names.h>
#include "openssl/opensslv.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>

uint32_t Utils::string2byte(const std::string& str, std::uint8_t* buf) {
    std::string str_no_space = str;
    str_no_space.erase(std::remove(str_no_space.begin(), str_no_space.end(), ' '), str_no_space.end());
    std::istringstream iss(str_no_space);
    std::string byte_str;
    std::vector<uint8_t> bytes;
    bytes.reserve(str_no_space.size() / 2 + 1);
    for (size_t i = 0; i < str_no_space.size(); i += 2) {
        byte_str = str_no_space.substr(i, 2);
        uint8_t byte = std::stoi(byte_str, nullptr, 16);
        bytes.push_back(byte);
    }
    std::copy(bytes.begin(), bytes.end(), buf);
    return static_cast<uint32_t>(bytes.size());
}

std::vector<std::uint8_t>
Utils::string2byte(
        const string &str) {
    std::string str_no_space = str;
    str_no_space.erase(std::remove(str_no_space.begin(), str_no_space.end(), ' '), str_no_space.end());
    std::istringstream iss(str_no_space);
    std::string byte_str;
    std::vector<uint8_t> bytes;
    bytes.reserve(str_no_space.size() / 2 + 1);
    for (size_t i = 0; i < str_no_space.size(); i += 2) {
        byte_str = str_no_space.substr(i, 2);
        uint8_t byte = std::stoi(byte_str, nullptr, 16);
        bytes.push_back(byte);
    }
    return std::move(bytes);
}

string Utils::Dword2String(std::uint32_t dw) {
    std::uint32_t dwData = dw;
    std::uint32_t dwData2 = 0x80 * 0x80 * 0x80 * 0x80;
    int nLen = 4;
    uint8_t hex[5] = { 0 };
    std::uint32_t dwOutLen = 0;

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

vector<uint8_t> Utils::VBEncode(unsigned int num) {
    vector<uint8_t> result;
    uint8_t b;
    while (num >= 128) {
        int a = num % 128;
        bitset<8> byte(a);
        byte.flip(7);
        num = (num - a) / 128;
        b = byte.to_ulong();
        cout << byte << endl;
        result.push_back(b);
    }
    int a = num % 128;
    bitset<8> byte(a);
    cout << byte << endl;
    b = byte.to_ulong();
    result.push_back(b);
    return result;
}


void Utils::print_hex(uint8_t *data, uint32_t len) {
    ::printf("\r\n");
    for (int i = 0; i < len; i++) {
        printf("0x%02x ", data[i]);
    }
    ::printf("\r\n");
}

string Utils::byte2string(const std::uint8_t *buf, std::size_t buf_size) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < buf_size; i++) {
        oss << std::setw(2) << static_cast<int>(buf[i]);
    }
    return oss.str();
}

uint32_t Utils::stringToUint32(const string &str) {
    std::stringstream ss(str);
    uint32_t value = 0;

    ss >> std::hex >> value;

    if (ss.fail()) {
        throw std::invalid_argument("Invalid input: " + str);
    }

    return value;
}
uint64_t Utils::stringToUint64(const std::string& str) {
    std::stringstream ss(str);
    uint64_t value = 0;

    ss >> std::hex >> value;

    if (ss.fail()) {
        throw std::invalid_argument("Invalid input: " + str);
    }

    return value;
}

void Utils::splitString(const string &input, char delimiter, vector<std::string> &output) {
    std::stringstream ss(input);
    std::string token;

    while (std::getline(ss, token, delimiter)) {
        output.push_back(token);
    }
}

void Utils::RemoveBrackets(string &str) {
    size_t startPos = str.find('[');
    size_t endPos = str.find(']');
    if (startPos != std::string::npos && endPos != std::string::npos && endPos > startPos) {
        str = str.substr(startPos + 1, endPos - startPos - 1);
    }

}

std::string Utils::GenerateUUID() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dis(0, 0xFFFFFFFF);
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 4; i++) {
        uint32_t random_num = dis(gen);
        ss << std::setw(8) << random_num;
        if (i < 3) {
            ss << "-";
        }
    }
    std::string uuid_str = ss.str();
    return uuid_str;
}

bool
Utils::ReadFileContent(
        std::string file_path,
        vector<::uint8_t> &buffer) {
    std::ifstream file;
    file.open(file_path,std::iostream::binary);
    if (!file.is_open()) {
        return false;
    }
    // 获取文件大小
    file.seekg(0, ios::end);
    int file_size = file.tellg();
    file.seekg(0, ios::beg);


    buffer.resize(file_size);
    file.read(reinterpret_cast<char *>(buffer.data()), file_size);
    file.close();
    return true;
}

std::string
Utils::MD5(
        const std::uint8_t *data,std::uint8_t data_size) {

    EVP_MD_CTX*   context = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_md5();
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int  md_len;
    string        output;

    EVP_DigestInit_ex2(context, md, NULL);
    EVP_DigestUpdate(context, data, data_size);
    EVP_DigestFinal_ex(context, md_value, &md_len);
    EVP_MD_CTX_free(context);

    output.resize(md_len * 2);
    for (unsigned int i = 0 ; i < md_len ; ++i)
        std::sprintf(&output[i * 2], "%02x", md_value[i]);
    return output;
}

///
/// \param data
/// \param data_size
/// \return 返回sha256的字符串值
std::string Utils::sha256(const std::uint8_t *data,const std::uint8_t data_size) {
    EVP_MD_CTX*   context = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_sha256();

//    const EVP_MD* md = EVP_sha512_256();
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int  md_len;
    string        output;
    EVP_DigestInit_ex2(context, md, NULL);
    EVP_DigestUpdate(context, data, data_size);
    EVP_DigestFinal_ex(context, md_value, &md_len);

    output.resize(md_len * 2);
    for (unsigned int i = 0 ; i < md_len ; ++i)
        std::sprintf(&output[i * 2], "%02x", md_value[i]);

    EVP_MD_CTX_free(context);
    return output;

}

///
/// \param data
/// \param data_size
/// \param out_buff  返回原始字节
void Utils::sha256(
        const std::uint8_t *data,
        const std::uint8_t data_size,
        std::vector<std::uint8_t>& out_buff) {
    EVP_MD_CTX*   context = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_sha256();
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int  md_len;

    EVP_DigestInit_ex2(context, md, NULL);
    EVP_DigestUpdate(context, data, data_size);
    EVP_DigestFinal_ex(context, out_buff.data(), &md_len);
    out_buff.resize(md_len);

    EVP_MD_CTX_free(context);

}

unsigned long
Utils::getULongTimeStmp() {
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    unsigned long timestamp_ull = static_cast<unsigned long>(timestamp);
    return timestamp_ull;
}

std::string Utils::base64_encode(
        const std::string& data) {
    static constexpr char sEncodingTable[] = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
            'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
            'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
            'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
            'w', 'x', 'y', 'z', '0', '1', '2', '3',
            '4', '5', '6', '7', '8', '9', '+', '/'
    };

    size_t in_len = data.size();
    size_t out_len = 4 * ((in_len + 2) / 3);
    std::string ret(out_len, '\0');
    size_t i;
    char *p = const_cast<char*>(ret.c_str());

    for (i = 0; i < in_len - 2; i += 3) {
        *p++ = sEncodingTable[(data[i] >> 2) & 0x3F];
        *p++ = sEncodingTable[((data[i] & 0x3) << 4) | ((int) (data[i + 1] & 0xF0) >> 4)];
        *p++ = sEncodingTable[((data[i + 1] & 0xF) << 2) | ((int) (data[i + 2] & 0xC0) >> 6)];
        *p++ = sEncodingTable[data[i + 2] & 0x3F];
    }
    if (i < in_len) {
        *p++ = sEncodingTable[(data[i] >> 2) & 0x3F];
        if (i == (in_len - 1)) {
            *p++ = sEncodingTable[((data[i] & 0x3) << 4)];
            *p++ = '=';
        }
        else {
            *p++ = sEncodingTable[((data[i] & 0x3) << 4) | ((int) (data[i + 1] & 0xF0) >> 4)];
            *p++ = sEncodingTable[((data[i + 1] & 0xF) << 2)];
        }
        *p++ = '=';
    }

    return ret;
}

void Utils::base64_decode(const std::string& input, std::string& out) {
    static constexpr unsigned char kDecodingTable[] = {
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
            52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
            64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
            15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
            64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
    };

    size_t in_len = input.size();
    if (in_len % 4 != 0) return; //错误返回

    size_t out_len = in_len / 4 * 3;
    if (input[in_len - 1] == '=') out_len--;
    if (input[in_len - 2] == '=') out_len--;

    out.resize(out_len);

    for (size_t i = 0, j = 0; i < in_len;) {
        uint32_t a = input[i] == '=' ? 0 & i++ : kDecodingTable[static_cast<int>(input[i++])];
        uint32_t b = input[i] == '=' ? 0 & i++ : kDecodingTable[static_cast<int>(input[i++])];
        uint32_t c = input[i] == '=' ? 0 & i++ : kDecodingTable[static_cast<int>(input[i++])];
        uint32_t d = input[i] == '=' ? 0 & i++ : kDecodingTable[static_cast<int>(input[i++])];

        uint32_t triple = (a << 3 * 6) + (b << 2 * 6) + (c << 1 * 6) + (d << 0 * 6);

        if (j < out_len) out[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < out_len) out[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < out_len) out[j++] = (triple >> 0 * 8) & 0xFF;
    }
}


/// outputLength 大于32字节可能会出错
/// \param psk
/// \param info
/// \param outputLength
/// \return
std::vector<std::uint8_t> Utils::HKDF(const std::vector<std::uint8_t>& psk,
                 const std::vector<std::uint8_t>& info,
                 int outputLength) {

    std::vector<std::uint8_t> result(outputLength, 0);

    const EVP_MD* md = EVP_sha256();
    unsigned int md_len = EVP_MD_size(md);
    if (md_len == 0) { // EVP_MD_size 返回 0 表示摘要算法无效
        return result;
    }
    int n = (outputLength + md_len - 1) / md_len; // 计算需要多少轮
    if (n > 0xFF) { // 最多支持 255 轮
        return result;
    }
    std::vector<unsigned char> hmac_data;


    std::vector<unsigned char> hmac_result(md_len, 0);
    int pos = 0;
    for (int i = 1; i <= n; i++) {
        hmac_data.resize(0);  //清空全部内容
        if(i!=1){
            hmac_data.reserve(info.size() +md_len+ 1);                          //预留足够的空间
            hmac_data.insert(hmac_data.begin(), hmac_result.begin(), hmac_result.end());//填充上一次结果
        }else{ //第一次不需要填充上一次的结果
            hmac_data.reserve(info.size() + 1);                          //预留足够的空间

        }
        hmac_data.insert(hmac_data.end(), info.begin(), info.end());//填充inof


        hmac_data.push_back(i);
        HMAC(md, psk.data(), psk.size(), hmac_data.data(), hmac_data.size(), hmac_result.data(), NULL);
        int copy_len = std::min<int>(md_len, outputLength - pos);
        memcpy(result.data() + pos, hmac_result.data(), copy_len);
        pos += copy_len;
        hmac_data.pop_back();
    }

    return std::move(result);


}

std::vector<std::uint8_t>
Utils::generateRandomBytes(
        std::uint32_t num_bytes) {

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    std::vector<uint8_t> bytes(num_bytes);
    for(size_t i = 0; i < num_bytes; ++i) {
        bytes[i] = static_cast<uint8_t>(dis(gen));
    }
    return std::move(bytes);
}





