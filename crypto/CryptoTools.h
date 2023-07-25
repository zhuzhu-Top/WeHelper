//
// Created by 28264 on 2023/5/27.
//

#ifndef WEHELPER_CRYPTOTOOLS_H
#define WEHELPER_CRYPTOTOOLS_H


#include <openssl/aes.h>
#include "../include/aes.hpp"
#include "../common/ByteBuffer.hpp"


class CryptoTools {


public:

    #define AES_BLOCK_SIZE 16
    static int Enc_AES_CBC(const unsigned char* plaintext, int plaintext_len, const unsigned char* key,
                           const unsigned char* iv, unsigned char* ciphertext);
    static int Dec_AES_CBC(unsigned char* plaintext, int plaintext_len, unsigned char* key,
                       unsigned char* iv, unsigned char* ciphertext);
    static int Dec_AES_ECB(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
                           unsigned char* plaintext);


    static void MD5(const uint8_t* initial_msg, size_t initial_len, uint8_t* digest);



    static bb::ByteBuffer RSA_Pub_Enc(bb::ByteBuffer& plaint_txt,std::string& str_n);
};


#endif //WEHELPER_CRYPTOTOOLS_H
