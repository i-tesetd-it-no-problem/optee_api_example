#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tee_client_api.h>

#include "../ta/include/aes_gcm_ccm.h"

#define BUFFER_SIZE 256

// 原始明文数据
char plain_text[] = "AES-GCM and AES-CCM examples";

// 用于存储密文和解密后的明文
char cipher_text[BUFFER_SIZE] = {0};
char tmp_buffer[BUFFER_SIZE] = {0};

struct aes_gcm_ccm_ctx {
    TEEC_Context ctx;               // TEE 上下文
    TEEC_Session sess;              // TEE 会话
    uint8_t aes_key[AES_KEY_BYTES_SIZE]; // AES 密钥
    uint8_t aes_iv[AES_IV_BYTES_SIZE];   // AES 初始化向量（IV）
};

static void prepare_tee_session(struct aes_gcm_ccm_ctx *ctx)
{
    if (!ctx)
        return;

    TEEC_UUID uuid = TA_AES_GCM_CCM_UUID;
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

    // 初始化密钥和 IV，这里使用示例数据，实际应用中应使用安全生成的密钥和随机 IV
    memset(ctx->aes_key, 0x5A, AES_KEY_BYTES_SIZE); // 设置示例密钥，填充为 0x5A
    memset(ctx->aes_iv, 0xA5, AES_IV_BYTES_SIZE);   // 设置示例 IV，填充为 0xA5
}

static void terminate_tee_session(struct aes_gcm_ccm_ctx *ctx)
{
    if (!ctx)
        return;

    TEEC_CloseSession(&ctx->sess);
    TEEC_FinalizeContext(&ctx->ctx);
}

// 准备 AES 环境
static void prepare_aes(struct aes_gcm_ccm_ctx *ctx, uint8_t algorithm, uint8_t cipher_mode)
{
    if (!ctx)
        return;

    // 本案例只支持AES-GCM AES-CCM
    if (algorithm != AES_ALGORITHM_GCM && algorithm != AES_ALGORITHM_CCM)
        return;

    if (cipher_mode != AES_CIPHER_MODE_ENCRYPT && cipher_mode != AES_CIPHER_MODE_DECRYPT)
        return;

    TEEC_Result ret;
    TEEC_Operation op;
    uint32_t origin_err;

    memset(&op, 0, sizeof(op));

    // 设置参数类型
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_VALUE_INPUT,       // param[0]: algorithm
        TEEC_VALUE_INPUT,       // param[1]: cipher_mode
        TEEC_MEMREF_TEMP_INPUT, // param[2]: key
        TEEC_NONE);

    op.params[0].value.a = algorithm;           // 算法类型（GCM 或 CCM）
    op.params[1].value.a = cipher_mode;         // 加密或解密模式
    op.params[2].tmpref.buffer = ctx->aes_key;  // AES 密钥
    op.params[2].tmpref.size = AES_KEY_BYTES_SIZE; // 密钥长度

    // 初始化加/解密环境
    ret = TEEC_InvokeCommand(&ctx->sess, TA_AES_GCM_CCM_CMD_PREPARE, &op, &origin_err);
    if (ret != TEEC_SUCCESS) {
        printf("TA_AES_GCM_CCM_CMD_PREPARE failed with code 0x%x origin 0x%x\n", ret, origin_err);
        exit(1);
    }
}

// 初始化 AES 参数，包括 IV、标签长度、AAD 长度和有效载荷长度
static void init_aes(struct aes_gcm_ccm_ctx *ctx, uint32_t tag_len, uint32_t aad_len, uint32_t payload_len)
{
    if (!ctx)
        return;

    TEEC_Result ret;
    TEEC_Operation op;
    uint32_t origin_err;

    memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_INPUT, // param[0]: IV
            TEEC_VALUE_INPUT,       // param[1]: tag_len aad_len
            TEEC_VALUE_INPUT,		// param[2]: payload_len
            TEEC_NONE);
	op.params[0].tmpref.buffer = ctx->aes_iv;    // 初始化向量（IV）
        op.params[0].tmpref.size = AES_IV_BYTES_SIZE; // IV 长度
        op.params[1].value.a = tag_len;  
        op.params[1].value.b = aad_len;
        op.params[2].value.a = payload_len;
    
    ret = TEEC_InvokeCommand(&ctx->sess, TA_AES_GCM_CCM_CMD_INIT, &op, &origin_err);
    if (ret != TEEC_SUCCESS) {
        printf("TA_AES_GCM_CCM_CMD_INIT failed with code 0x%x origin 0x%x\n", ret, origin_err);
        exit(1);
    }
}


// AES 认证加密
static void aes_encrypt(struct aes_gcm_ccm_ctx *ctx, uint8_t *in, size_t in_len,
                        uint8_t *out, size_t *out_len, uint8_t *tag, size_t *tag_len)
{
    if (!ctx || !in || !out || !out_len || !tag || !tag_len)
        return;

    TEEC_Result ret;
    TEEC_Operation op;
    uint32_t origin_err;

    memset(&op, 0, sizeof(op));

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,  // param[0]: 明文输入
        TEEC_MEMREF_TEMP_OUTPUT, // param[1]: 密文输出
        TEEC_MEMREF_TEMP_OUTPUT, // param[2]: 认证标签输出
        TEEC_NONE);

    op.params[0].tmpref.buffer = in;         // 输入明文数据
    op.params[0].tmpref.size = in_len;       // 明文长度
    op.params[1].tmpref.buffer = out;        // 输出密文缓冲区
    op.params[1].tmpref.size = *out_len;     // 密文缓冲区大小
    op.params[2].tmpref.buffer = tag;        // 输出认证标签缓冲区
    op.params[2].tmpref.size = *tag_len;     // 认证标签缓冲区大小

    // 认证加密
    ret = TEEC_InvokeCommand(&ctx->sess, TA_AES_GCM_CCM_CMD_ENCRYPT, &op, &origin_err);
    if (ret != TEEC_SUCCESS) {
        printf("TA_AES_GCM_CCM_CMD_ENCRYPT failed with code 0x%x origin 0x%x\n", ret, origin_err);
        exit(1);
    }

    // 更新实际输出的密文长度和标签长度
    *out_len = op.params[1].tmpref.size;
    *tag_len = op.params[2].tmpref.size;
}

// AES 认证解密
static void aes_decrypt(struct aes_gcm_ccm_ctx *ctx, uint8_t *in, size_t in_len,
                        uint8_t *out, size_t *out_len, uint8_t *tag, size_t tag_len)
{
    if (!ctx || !in || !out || !out_len || !tag)
        return;

    TEEC_Result ret;
    TEEC_Operation op;
    uint32_t origin_err;

    memset(&op, 0, sizeof(op));

    // 设置参数类型
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,  // param[0]: 密文输入
        TEEC_MEMREF_TEMP_OUTPUT, // param[1]: 明文输出
        TEEC_MEMREF_TEMP_INPUT,  // param[2]: 认证标签输入
        TEEC_NONE);

    // 设置参数值
    op.params[0].tmpref.buffer = in;         // 输入密文数据
    op.params[0].tmpref.size = in_len;       // 密文长度
    op.params[1].tmpref.buffer = out;        // 输出明文缓冲区
    op.params[1].tmpref.size = *out_len;     // 明文缓冲区大小
    op.params[2].tmpref.buffer = tag;        // 输入认证标签
    op.params[2].tmpref.size = tag_len;      // 认证标签长度

    // 认证解密
    ret = TEEC_InvokeCommand(&ctx->sess, TA_AES_GCM_CCM_CMD_DECRYPT, &op, &origin_err);
    if (ret != TEEC_SUCCESS) {
        printf("TA_AES_GCM_CCM_CMD_DECRYPT failed with code 0x%x origin 0x%x\n", ret, origin_err);
        exit(1);
    }

    // 更新实际输出的明文长度
    *out_len = op.params[1].tmpref.size;
}

// AES-GCM 示例
static void aes_gcm_example(struct aes_gcm_ccm_ctx *ctx)
{
    size_t encrypt_len = BUFFER_SIZE; // 密文缓冲区大小
    size_t decrypt_len = BUFFER_SIZE; // 明文缓冲区大小
    uint8_t tag[AES_TAG_BYTES_SIZE];  // 认证标签
    size_t tag_len = AES_TAG_BYTES_SIZE; // 认证标签长度

    printf("AES-GCM Example\n");

    /* 初始化 AES-GCM 加密环境 */
	prepare_aes(ctx, AES_ALGORITHM_GCM, AES_CIPHER_MODE_ENCRYPT);
	/* 初始化 AES 参数 */
	init_aes(ctx, AES_TAG_BYTES_SIZE, 0, 0);

    /* 认证加密 */
    aes_encrypt(ctx, (uint8_t *)plain_text, strlen(plain_text),
                (uint8_t *)cipher_text, &encrypt_len, tag, &tag_len);

    /* 加密结果 */
    printf("Plain Text: %s\n", plain_text);
	printf("Cipher Text Size is %d\n", encrypt_len);
    printf("Cipher Text (hex): ");
    for (size_t i = 0; i < encrypt_len; i++)
        printf("%02X ", (uint8_t)cipher_text[i]);
    printf("\n");
    printf("Tag (hex): ");
    for (size_t i = 0; i < tag_len; i++)
        printf("%02X ", tag[i]);
    printf("\n\n");

    /* 初始化 AES-GCM 解密环境 */
    prepare_aes(ctx, AES_ALGORITHM_GCM, AES_CIPHER_MODE_DECRYPT);
    /* 初始化 AES 参数 */
    init_aes(ctx, AES_TAG_BYTES_SIZE, 0, 0);

    /* 认证解密 */
    aes_decrypt(ctx, (uint8_t *)cipher_text, encrypt_len,
                (uint8_t *)tmp_buffer, &decrypt_len, tag, tag_len);
	tmp_buffer[decrypt_len] = '\0';
    printf("Decrypted Text: %s\n\n", tmp_buffer);
}

// AES-CCM 示例
// AES-CCM 示例
static void aes_ccm_example(struct aes_gcm_ccm_ctx *ctx)
{
    size_t encrypt_len = BUFFER_SIZE; // 密文缓冲区大小
    size_t decrypt_len = BUFFER_SIZE; // 明文缓冲区大小
    uint8_t tag[AES_TAG_BYTES_SIZE];  // 认证标签
    size_t tag_len = AES_TAG_BYTES_SIZE; // 认证标签长度

    printf("AES-CCM Example\n");

    /* 初始化 AES-CCM 加密环境 */
    prepare_aes(ctx, AES_ALGORITHM_CCM, AES_CIPHER_MODE_ENCRYPT);
    /* 初始化 AES 参数，包括 tag_len, aad_len 和 payload_len */
    init_aes(ctx, AES_TAG_BYTES_SIZE, 0, strlen(plain_text));

    /* 认证加密 */
    aes_encrypt(ctx, (uint8_t *)plain_text, strlen(plain_text),
                (uint8_t *)cipher_text, &encrypt_len, tag, &tag_len);

    /* 加密结果 */
    printf("Plain Text: %s\n", plain_text);
    printf("Cipher Text Size: %zu\n", encrypt_len);
    printf("Cipher Text (hex): ");
    for (size_t i = 0; i < encrypt_len; i++)
        printf("%02X ", (uint8_t)cipher_text[i]);
    printf("\n");
    printf("Tag (hex): ");
    for (size_t i = 0; i < tag_len; i++)
        printf("%02X ", tag[i]);
    printf("\n\n");

    /* 初始化 AES-CCM 解密环境 */
    prepare_aes(ctx, AES_ALGORITHM_CCM, AES_CIPHER_MODE_DECRYPT);
    /* 初始化 AES 参数，包括 tag_len, aad_len 和 payload_len */
    init_aes(ctx, AES_TAG_BYTES_SIZE, 0, encrypt_len);

    /* 认证解密 */
    aes_decrypt(ctx, (uint8_t *)cipher_text, encrypt_len,
                (uint8_t *)tmp_buffer, &decrypt_len, tag, tag_len);
    tmp_buffer[decrypt_len] = '\0';
    printf("Decrypted Text: %s\n\n", tmp_buffer);
}


int main()
{
    struct aes_gcm_ccm_ctx ctx;

    prepare_tee_session(&ctx); // 初始化 TEE 会话

    aes_gcm_example(&ctx);     // 运行 AES-GCM 示例

    aes_ccm_example(&ctx);     // 运行 AES-CCM 示例

    terminate_tee_session(&ctx); // 结束 TEE 会话

    return 0;
}
