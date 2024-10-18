#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tee_client_api.h>

#include "../ta/include/symmetric_cipher.h"

char *aes_info[SYMM_CIPHER_ALG_MAX] = {
    [SYMM_CIPHER_ALG_AES_ECB_NOPAD] = "AES ECB NOPAD",
    [SYMM_CIPHER_ALG_AES_CBC_NOPAD] = "AES CBC NOPAD",
    [SYMM_CIPHER_ALG_AES_CTR] = "AES CTR",
    [SYMM_CIPHER_ALG_AES_CTS] = "AES CTS",
    [SYMM_CIPHER_ALG_AES_XTS] = "AES XTS",
};

/* 明文内容 */
char *plain_text = "AES Cipher Algorithm Examples"; // CTS 模式明文至少需要一个块大小 即16字节

/* 缓冲区大 */
#define BUFFER_SIZE 256

/* AES块大小（16字节） */
#define AES_BLOCK_SIZE (16)

/* 16字节对齐 */
#define ROUND_BLOCK_SIZE(len) \
    (((len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE)

static bool no_need_round(enum symm_cipher_alg alg)
{
	return (alg == SYMM_CIPHER_ALG_AES_CTR || alg == SYMM_CIPHER_ALG_AES_CTS);
}

/* 加密缓冲 */
size_t encrype_len = 0;
uint8_t encrypt_buffer[BUFFER_SIZE];

struct symmetric_cipher_ctx {
    TEEC_Context ctx;
    TEEC_Session sess;
};

/**
 * @brief 生成对称加密密钥
 *
 * @param ctx 对称加密上下文
 * @param alg 选择的加密算法
 */
static void generate_key(struct symmetric_cipher_ctx *ctx, enum symm_cipher_alg alg)
{
    TEEC_Operation op;
    TEEC_Result ret;
    uint32_t error_origin;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_VALUE_INPUT, 
        TEEC_NONE, 
        TEEC_NONE, 
        TEEC_NONE
    );
    op.params[0].value.a = (uint32_t)alg;

    ret = TEEC_InvokeCommand(&ctx->sess, SYMM_CIPHER_CMD_GEN, &op, &error_origin);
    if(ret != TEEC_SUCCESS) {
        errx(1, "TEEC_InvokeCommand (GEN) failed with code 0x%x origin 0x%x", ret, error_origin);
    }
}

/**
 * @brief 执行加密操作
 *
 * @param ctx 对称加密上下文
 * @param alg 选择的加密算法
 */
static void encrypto(struct symmetric_cipher_ctx *ctx, enum symm_cipher_alg alg)
{
    TEEC_Operation op;
    TEEC_Result ret;
    uint32_t error_origin;

    memset(&op, 0, sizeof(op));

    /* 判断是否需要对齐 */
    bool flag = no_need_round(alg);

    /* 获取明文长度及对齐后的长度 */
    size_t plain_len = strlen(plain_text);
    size_t rounded_len = ROUND_BLOCK_SIZE(plain_len);

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, 
        TEEC_MEMREF_TEMP_OUTPUT, 
        TEEC_NONE, 
        TEEC_NONE
    );

    op.params[0].tmpref.buffer = (void *)plain_text;
    op.params[0].tmpref.size = flag ? plain_len : rounded_len;
    op.params[1].tmpref.buffer = encrypt_buffer;
    op.params[1].tmpref.size = flag ? plain_len : rounded_len;

    ret = TEEC_InvokeCommand(&ctx->sess, SYMM_CIPHER_CMD_ENCRYP, &op, &error_origin);
    if(ret != TEEC_SUCCESS) {
        errx(1, "TEEC_InvokeCommand (ENCRYP) failed with code 0x%x origin 0x%x", ret, error_origin);
    }

    /* 加密后的长度 */
    encrype_len = op.params[1].tmpref.size;

    printf("\nPlain text: %s\n", plain_text);
    printf("Encrypted size: %zu bytes\n", encrype_len);
    printf("Encrypted text (hex):\n");
    for(size_t i = 0; i < encrype_len; i++) {
        printf("%02x", encrypt_buffer[i]);
    }
    printf("\n\n");
}

/**
 * @brief 执行解密操作
 *
 * @param ctx 对称加密上下文
 * @param alg 选择的加密算法
 */
static void decrypto(struct symmetric_cipher_ctx *ctx, enum symm_cipher_alg alg)
{
    TEEC_Operation op;
    TEEC_Result ret;
    uint32_t error_origin;
    
    /* 解密参数 */
    size_t decrypt_len = 0;
    uint8_t decrypt_buffer[BUFFER_SIZE];
    
    /* 判断是否需要对齐 */
    bool flag = no_need_round(alg);
    
    /* 获取密文长度及对齐后的长度 */
    size_t cipher_len = encrype_len;
    size_t rounded_cipher_len = ROUND_BLOCK_SIZE(cipher_len);

    memset(&op, 0, sizeof(op));

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, 
        TEEC_MEMREF_TEMP_OUTPUT, 
        TEEC_NONE, 
        TEEC_NONE
    );

    op.params[0].tmpref.buffer = encrypt_buffer;
    op.params[0].tmpref.size = flag ? cipher_len : rounded_cipher_len;
    op.params[1].tmpref.buffer = decrypt_buffer;
    op.params[1].tmpref.size = flag ? cipher_len : rounded_cipher_len;

    ret = TEEC_InvokeCommand(&ctx->sess, SYMM_CIPHER_CMD_DECRYP, &op, &error_origin);
    if(ret != TEEC_SUCCESS) {
        errx(1, "TEEC_InvokeCommand (DECRYP) failed with code 0x%x origin 0x%x", ret, error_origin);
    }

    /* 解密后的长度 */
    decrypt_len = op.params[1].tmpref.size;

    if(decrypt_len >= BUFFER_SIZE) {
        decrypt_len = BUFFER_SIZE - 1;
    }
    decrypt_buffer[decrypt_len] = '\0';
    printf("Decrypted text:\n%s\n", decrypt_buffer);
}

/**
 * @brief 运行对称加密示例，包括生成密钥、加密和解密
 *
 * @param ctx 对称加密上下文
 * @param alg 选择的加密算法
 */
static void symm_example(struct symmetric_cipher_ctx *ctx, enum symm_cipher_alg alg)
{
    printf("------------------------------%s------------------------------\n", aes_info[alg]);
    generate_key(ctx, alg);   // 生成密钥
    encrypto(ctx, alg);       // 执行加密
    decrypto(ctx, alg);       // 执行解密
}

static void prepare_tee_session(struct symmetric_cipher_ctx *ctx)
{
    TEEC_UUID uuid = TA_SYMMETRIC_CIPHER_UUID;
    uint32_t origin;
    TEEC_Result res;

    res = TEEC_InitializeContext(NULL, &ctx->ctx);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InitializeContext failed with code 0x%x\n", res);
        exit(1);
    }

    res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_OpenSession failed with code 0x%x origin 0x%x\n", res, origin);
        TEEC_FinalizeContext(&ctx->ctx);
        exit(1);
    }
}

static void terminate_tee_session(struct symmetric_cipher_ctx *ctx)
{
    TEEC_CloseSession(&ctx->sess);
    TEEC_FinalizeContext(&ctx->ctx);
}


int main()
{
    struct symmetric_cipher_ctx ctx;

    prepare_tee_session(&ctx);

    /*
        SYMM_CIPHER_ALG_AES_ECB_NOPAD,
        SYMM_CIPHER_ALG_AES_CBC_NOPAD,
        SYMM_CIPHER_ALG_AES_CTR,
        SYMM_CIPHER_ALG_AES_CTS,
        SYMM_CIPHER_ALG_AES_XTS,
    */
    symm_example(&ctx, SYMM_CIPHER_ALG_AES_ECB_NOPAD);
    symm_example(&ctx, SYMM_CIPHER_ALG_AES_CBC_NOPAD);
    symm_example(&ctx, SYMM_CIPHER_ALG_AES_CTR);
    symm_example(&ctx, SYMM_CIPHER_ALG_AES_CTS);
    symm_example(&ctx, SYMM_CIPHER_ALG_AES_XTS);

    terminate_tee_session(&ctx);

    return 0;
}
