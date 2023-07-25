//
// Created by 28264 on 2023/5/30.
//

#ifndef WEHELPER_AES_GCM_H
#define WEHELPER_AES_GCM_H
#include "../include/pub_include.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/aes.h>


class AES_GCM {

public:
    static std::unique_ptr<unsigned char[]> aes_gcm_encrypt(const uint8_t *plaintext, uint32_t plaintext_length,
                                                     const uint8_t *gcm_key,
                                                     const uint8_t * gcm_iv,uint32_t iv_len,
                                                     const uint8_t * gcm_aad,uint32_t aad_len,
                                                     uint32_t* out_length,
                                                     uint8_t *tag);

    static bool aes_gcm_decrypt(const uint8_t *ciphertext , uint32_t ciphertext_length,
                                         const uint8_t *gcm_key,
                                         const uint8_t * gcm_iv,uint32_t iv_len,
                                         const uint8_t * gcm_aad,uint32_t aad_len,
                                         const uint8_t *tag,
                                std::vector<uint8_t>& ret_value);
};


#endif //WEHELPER_AES_GCM_H
