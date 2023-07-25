//
// Created by 28264 on 2023/5/30.
//

#include "AES_GCM.h"

std::unique_ptr<unsigned char[]> AES_GCM::aes_gcm_encrypt(const uint8_t *plaintext, uint32_t plaintext_length,
                                                          const uint8_t *gcm_key,
                                                          const uint8_t * gcm_iv,uint32_t iv_len,
                                                          const uint8_t * gcm_aad,uint32_t aad_len,
                                                          uint32_t* out_length,
                                                          uint8_t *tag)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, gcm_key, gcm_iv);

    int ciphertext_length = plaintext_length + EVP_CIPHER_CTX_block_size(ctx);
    std::unique_ptr<unsigned char[]> ciphertext(new unsigned char[ciphertext_length]);

    int outlen=0x0;
    EVP_EncryptUpdate(ctx, NULL, &outlen, gcm_aad, aad_len);
    EVP_EncryptUpdate(ctx, ciphertext.get(), &outlen, plaintext, plaintext_length);
    *out_length = outlen;

    EVP_EncryptFinal_ex(ctx, ciphertext.get(), &outlen);
    *out_length += outlen;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

///
/// \param ciphertext
/// \param ciphertext_length
/// \param gcm_key
/// \param gcm_iv
/// \param iv_len
/// \param gcm_aad   解密aad可以为空
/// \param aad_len
/// \param tag
/// \param ret_value  返回值不带tag
/// \return
bool AES_GCM::aes_gcm_decrypt(const uint8_t *ciphertext , uint32_t ciphertext_length,
                                                          const uint8_t *gcm_key,
                                                          const uint8_t * gcm_iv,uint32_t iv_len,
                                                          const uint8_t * gcm_aad,uint32_t aad_len,
                                                          const uint8_t *tag,
                                                          std::vector<uint8_t>& ret_value) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, gcm_key, gcm_iv);

    int outlen = 0;
    if(gcm_aad!=
       nullptr){        //未验证
        EVP_DecryptUpdate(ctx, NULL, &outlen, gcm_aad, aad_len);
    }
    EVP_DecryptUpdate(ctx,ret_value.data(), &outlen, ciphertext, ciphertext_length);
    ret_value.resize(outlen-0x10);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

