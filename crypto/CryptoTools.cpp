//
// Created by 28264 on 2023/5/27.
//

#include "CryptoTools.h"

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>


int CryptoTools::Enc_AES_CBC(const unsigned char* plaintext, int plaintext_len, const unsigned char* key,
                             const unsigned char* iv, unsigned char* ciphertext) {
    if(plaintext==nullptr || key==nullptr ||  iv==nullptr ){
        throw "error";
    }
    int ciphertext_len = 0;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len);
    int final_len = 0;
    EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len);
    ciphertext_len += final_len;
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}
int CryptoTools::Dec_AES_CBC(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv,
                             unsigned char* plaintext) {

    int plaintext_len = 0;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, ciphertext, ciphertext_len);
    int final_len = 0;
    EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &final_len);
    plaintext_len += final_len;
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

// Constants are the integer part of the sines of integers (in radians) * 2^32.
const uint32_t k[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee ,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501 ,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be ,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa ,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8 ,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed ,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a ,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c ,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70 ,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05 ,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 ,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039 ,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1 ,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1 ,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

// r specifies the per-round shift amounts
const uint32_t r[] = { 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                       5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                       4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                       6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 };

// leftrotate function definition
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))


void to_bytes(uint32_t val, uint8_t* bytes)
{
    bytes[0] = (uint8_t)val;
    bytes[1] = (uint8_t)(val >> 8);
    bytes[2] = (uint8_t)(val >> 16);
    bytes[3] = (uint8_t)(val >> 24);
}
uint32_t to_int32(const uint8_t* bytes)
{
    return (uint32_t)bytes[0]
           | ((uint32_t)bytes[1] << 8)
           | ((uint32_t)bytes[2] << 16)
           | ((uint32_t)bytes[3] << 24);
}

void CryptoTools::MD5(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest) {

    uint32_t h0, h1, h2, h3;

    // Message (to prepare)
    uint8_t* msg = NULL;

    size_t new_len, offset;
    uint32_t w[16];
    uint32_t a, b, c, d, i, f, g, temp;

    // Initialize variables - simple count in nibbles:
    h0 = 0x67452301;
    h1 = 0xefcdab89;
    h2 = 0x98badcfe;
    h3 = 0x10325476;

    //Pre-processing:
    //append "1" bit to message
    //append "0" bits until message length in bits ≡ 448 (mod 512)
    //append length mod (2^64) to message
    //                                          64        56
    for (new_len = initial_len + 1; new_len % (512 / 8) != 448 / 8; new_len++)
        ;
    msg = (uint8_t*)malloc(new_len + 8);
    memcpy(msg, initial_msg, initial_len);
    msg[initial_len] = 0x80; // append the "1" bit; most significant bit is "first"
    for (offset = initial_len + 1; offset < new_len; offset++)
        msg[offset] = 0; // append "0" bits

    // append the len in bits at the end of the buffer.
    to_bytes(initial_len * 8, msg + new_len);
    // initial_len>>29 == initial_len*8>>32, but avoids overflow.
    to_bytes(initial_len >> 29, msg + new_len + 4);

    // Process the message in successive 512-bit chunks:
    //for each 512-bit chunk of message:
    for (offset = 0; offset < new_len; offset += (512 / 8)) {

        // break chunk into sixteen 32-bit words w[j], 0 ≤ j ≤ 15
        for (i = 0; i < 16; i++)
            w[i] = to_int32(msg + offset + i * 4);

        // Initialize hash value for this chunk:
        a = h0;
        b = h1;
        c = h2;
        d = h3;

        // Main loop:
        for (i = 0; i < 64; i++) {

            if (i < 16) {
                f = (b & c) | ((~b) & d);
                g = i;
            }
            else if (i < 32) {
                f = (d & b) | ((~d) & c);
                g = (5 * i + 1) % 16;
            }
            else if (i < 48) {
                f = b ^ c ^ d;
                g = (3 * i + 5) % 16;
            }
            else {
                f = c ^ (b | (~d));
                g = (7 * i) % 16;
            }

            temp = d;
            d = c;
            c = b;
            b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
            a = temp;

        }

        // Add this chunk's hash to result so far:
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;

    }

    // cleanup
    free(msg);

    //var char digest[16] := h0 append h1 append h2 append h3 //(Output is in little-endian)
    to_bytes(h0, digest);
    to_bytes(h1, digest + 4);
    to_bytes(h2, digest + 8);
    to_bytes(h3, digest + 12);

}

bb::ByteBuffer
CryptoTools::RSA_Pub_Enc(bb::ByteBuffer& plaint_txt,std::string& str_n) {
//    std::uint8_t plaint_txt[]= {0x57,0x94,0x89,0x80,0xac,0x64,0xa0,0x4f,0x8e,0xa3,0x64,0x4d,0xcb,0xe5,0x67,0x9a};
//    std::uint32_t plaint_size = sizeof(plaint_txt) ;

    RSA * rsa = RSA_new();
    BIGNUM* n = BN_new();
    BIGNUM* e = BN_new();
    BN_hex2bn(&n,str_n.c_str());
    BN_hex2bn(&e,"010001");
    RSA_set0_key(rsa,n,e,0);
    int keysize = RSA_size(rsa);

    bb::ByteBuffer buffer(keysize);
    buffer.resize(keysize);
    int ret = RSA_public_encrypt(plaint_txt.size(),plaint_txt.getPtr(),buffer.getPtr(),rsa,1);
    buffer.resize(ret);



    RSA_free(rsa);
    // RSA_set0_key() 函数时已经被 RSA 对象所持有
//    BN_clear_free(n);
//    BN_clear_free(e);
//    std::cout<<buffer<<std::endl;
//    auto str_ret =buffer.getString();
    return std::move(buffer);
}

int
CryptoTools::Dec_AES_ECB(
        unsigned char *ciphertext,
        int ciphertext_len,
        unsigned char *key,
        unsigned char *plaintext) {

    int plaintext_len = 0;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL); // 填充缺少的参数 NULL
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7); // 设置填充模式
    if(!EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1; // 解密失败
    }
    int out_len = 0;
    if(!EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &out_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1; // 解密失败
    }
    plaintext_len += out_len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}
