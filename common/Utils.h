//
// Created by 28264 on 2023/5/27.
//

#ifndef WEHELPER_UTILS_H
#define WEHELPER_UTILS_H

#include <iostream>
#include <sstream>
#include <vector>
#include <bitset>
#include <iomanip>
#include <random>

#include <openssl/conf.h>

#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/aes.h>


using namespace std;
class Utils {

public:
    static __inline void removeSpace( std::string& str_no_space){
        str_no_space.erase(std::remove(str_no_space.begin(), str_no_space.end(), ' '), str_no_space.end());
    };
    static uint32_t string2byte(const std::string& str, std::uint8_t* buf);
    static std::vector<std::uint8_t> string2byte(const std::string& str);
    static string byte2string(const std::uint8_t* buf, std::size_t buf_size);

    static uint32_t stringToUint32(const std::string& str);
    static uint64_t stringToUint64(const std::string& str);

    static string Dword2String(uint32_t dw);
    static vector<uint8_t> VBEncode(unsigned int num);

    static std::string MD5(const std::uint8_t *data,std::uint8_t data_size);
    static std::string sha256(const std::uint8_t *data,const std::uint8_t data_size);
    static void sha256(const std::uint8_t *data,const std::uint8_t data_size,std::vector<std::uint8_t>& out_buff);
    static std::string base64_encode(const std::string& data);
    static void base64_decode(const std::string& input, std::string& out);
//     void HKDF(const unsigned char *info,int info_len, const unsigned char *key, int key_len, int output_length, unsigned char *output) ;
    static std::vector<std::uint8_t> HKDF(const std::vector<std::uint8_t>& psk,
                                   const std::vector<std::uint8_t>& info,
                                   int outputLength);

    static unsigned long getULongTimeStmp();

    static std::vector<std::uint8_t> generateRandomBytes(std::uint32_t num_bytes);

    #define AES_BLOCK_SIZE 16
    static int AES_CBC_Encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key,
                    unsigned char* iv, unsigned char* ciphertext);

    static void print_hex(uint8_t* data,uint32_t len);

    static void splitString(const std::string& input, char delimiter,std::vector<std::string>& output);

    static void RemoveBrackets(std::string& str);


    static std::string GenerateUUID();

    static bool ReadFileContent(std::string file_path,std::vector<::uint8_t>& buffer);


    template <typename T>
    static T swapEndian(T value)
    {
        static_assert(std::is_integral<T>::value && std::is_unsigned<T>::value,
                      "swapEndian only supports unsigned integral types");

        constexpr size_t size = sizeof(T);
        T result = 0;

        for (size_t i = 0; i < size; ++i)
        {
            result |= ((value >> (8 * (size - 1 - i))) & 0xFF) << (8 * i);
        }

        return result;
    }
};


#endif //WEHELPER_UTILS_H
