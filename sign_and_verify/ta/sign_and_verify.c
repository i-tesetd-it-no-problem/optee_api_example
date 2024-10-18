#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "include/sign_and_verify.h"

struct sigh_and_verify_session {
    TEE_OperationHandle sigh_operation; /* 签名操作句柄 */
    TEE_OperationHandle verify_operation; /* 验签操作句柄 */
    TEE_OperationHandle digest_operation; /* 摘要操作句柄 */
    TEE_ObjectHandle key_pair; /* 密钥对句柄 */
    enum sigh_verify_alg alg; /* 当前使用的算法 */
};

// 枚举转OPTEE签名算法
static uint32_t get_tee_sigh_alg(enum sigh_verify_alg alg)
{
    switch(alg) {
        case SIGH_VERIFY_ALG_RSASSA_PKCSV1_5_SHA256:
            return TEE_ALG_RSASSA_PKCS1_V1_5_SHA256;

        case SIGH_VERIFY_ALG_RSASSA_PKCSV1_PSS_MGF1_SHA256:
            return TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256;

        case SIGH_VERIFY_ALG_ECDSA_P256:
            return TEE_ALG_ECDSA_P256;

        case SIGH_VERIFY_ALG_ED25519:
            return TEE_ALG_ED25519;

        default:
            return 0XFFFFFFFF;
    }
}

// 获取密钥类型
static uint32_t get_key_type(enum sigh_verify_alg alg)
{
    switch(alg) {
        case SIGH_VERIFY_ALG_RSASSA_PKCSV1_5_SHA256:
        case SIGH_VERIFY_ALG_RSASSA_PKCSV1_PSS_MGF1_SHA256:
            return TEE_TYPE_RSA_KEYPAIR;

        case SIGH_VERIFY_ALG_ECDSA_P256:
            return TEE_TYPE_ECDSA_KEYPAIR;
        case SIGH_VERIFY_ALG_ED25519:
            return TEE_TYPE_ED25519_KEYPAIR;

        default:
            return 0XFFFFFFFF;
    }
}

// 枚举转OPTEE摘要算法
static uint32_t get_tee_digest_alg(enum sigh_verify_alg alg)
{
    switch(alg) {
        case SIGH_VERIFY_ALG_RSASSA_PKCSV1_5_SHA256:
        case SIGH_VERIFY_ALG_RSASSA_PKCSV1_PSS_MGF1_SHA256:
        case SIGH_VERIFY_ALG_ECDSA_P256:
            return TEE_ALG_SHA256;

        case SIGH_VERIFY_ALG_ED25519: // 这里只是为了能够跑过 TEE_IsAlgorithmSupported
            return TEE_ALG_SHA256;
        default:
            return 0XFFFFFFFF;
    }
}

static size_t get_key_pair_bits(enum sigh_verify_alg alg)
{
    // RSA 的密钥位数，可以根据实际需求调整
    // 256, 512, 768, 1024, 1536, 2048, 3072, 4096
    const size_t RSA_KEY_BITS = 1024;

    switch(alg) {
        case SIGH_VERIFY_ALG_RSASSA_PKCSV1_5_SHA256:
        case SIGH_VERIFY_ALG_RSASSA_PKCSV1_PSS_MGF1_SHA256:
            return RSA_KEY_BITS;

        case SIGH_VERIFY_ALG_ECDSA_P256:
        case SIGH_VERIFY_ALG_ED25519:
            // 固定为256位
            return 256;

        default:
            return 0;
    }
}

// 验证是否支持指定算法接口需要的参数
// 生成椭圆曲线密钥对时，需要的参数
static uint32_t get_tee_element(enum sigh_verify_alg type) 
{
    switch (type) {
        case SIGH_VERIFY_ALG_ECDSA_P256:    return TEE_ECC_CURVE_NIST_P256;  // NIST P-256 椭圆曲线
        case SIGH_VERIFY_ALG_ED25519:       return TEE_ECC_CURVE_25519;      // 25519 椭圆曲线
        default:                            return TEE_CRYPTO_ELEMENT_NONE;              // 未知类型，返回无效值
    }
}

// 释放资源
static void free_handle(struct sigh_and_verify_session *sess_ctx)
{
    struct sigh_and_verify_session *ctx = (struct sigh_and_verify_session *)sess_ctx;

    if(ctx->sigh_operation) {
        TEE_FreeOperation(ctx->sigh_operation);
        ctx->sigh_operation = TEE_HANDLE_NULL;
    }

    if(ctx->digest_operation) {
        TEE_FreeOperation(ctx->digest_operation);
        ctx->digest_operation = TEE_HANDLE_NULL;
    }

    if(ctx->key_pair) {
        TEE_FreeTransientObject(ctx->key_pair);
        ctx->key_pair = TEE_HANDLE_NULL;
    }
}

//生成密钥对
static TEE_Result gen_key_pair(struct sigh_and_verify_session *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    TEE_Result ret;
    TEE_Attribute attr;
    struct sigh_and_verify_session *ctx = (struct sigh_and_verify_session *)sess_ctx; /* 会话上下文 */

    // 验证参数类型
    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    if (param_types != exp_param_type) {
        EMSG("param_types is not correct\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ctx->alg = params[0].value.a; //保存算法类型

    // 验证摘要算法是否支持
    ret = TEE_IsAlgorithmSupported(get_tee_digest_alg(ctx->alg), TEE_CRYPTO_ELEMENT_NONE);
    if (ret != TEE_SUCCESS) {
        EMSG("Algorithm not supported\n");
        return ret;
    }

    // 验证签名算法是否支持
    ret = TEE_IsAlgorithmSupported(get_tee_sigh_alg(ctx->alg), get_tee_element(ctx->alg));
    if (ret != TEE_SUCCESS) {
        EMSG("Algorithm not supported\n");
        return ret;
    }

    free_handle(ctx); //释放之前的资源

    // 根据GP规范, 该椭圆曲线算法密钥生成需要这个参数
    if(ctx->alg == SIGH_VERIFY_ALG_ECDSA_P256) 
        TEE_InitValueAttribute(&attr, TEE_ATTR_ECC_CURVE, get_tee_element(ctx->alg), 0);

    // 申请瞬态对象
    ret = TEE_AllocateTransientObject(get_key_type(ctx->alg),get_key_pair_bits(ctx->alg), &ctx->key_pair);
    if(ret != TEE_SUCCESS) {
        EMSG("Allocate transient object failed\n");
        return ret;
    }

    // 生成密钥对
    if(ctx->alg == SIGH_VERIFY_ALG_ECDSA_P256)
        ret = TEE_GenerateKey(ctx->key_pair, get_key_pair_bits(ctx->alg), &attr, 1);
    else
        ret = TEE_GenerateKey(ctx->key_pair, get_key_pair_bits(ctx->alg), NULL, 0); // 其他类型不需要参数
    if(ret != TEE_SUCCESS) {
        EMSG("Generate key pair failed\n");
        TEE_FreeTransientObject(ctx->key_pair);
        return ret;
    }

    // 申请签名操作句柄
    ret = TEE_AllocateOperation(&ctx->sigh_operation, get_tee_sigh_alg(ctx->alg), TEE_MODE_SIGN, get_key_pair_bits(ctx->alg));
    if (ret != TEE_SUCCESS) {
        EMSG("Allocate operation failed\n");
        return ret;
    }

    // 设置签名密钥
    ret = TEE_SetOperationKey(ctx->sigh_operation, ctx->key_pair);
    if (ret != TEE_SUCCESS) {
        EMSG("Set operation key failed\n");
        TEE_FreeTransientObject(ctx->key_pair);
        return ret;
    }

    // 申请验签操作句柄
    ret = TEE_AllocateOperation(&ctx->verify_operation, get_tee_sigh_alg(ctx->alg), TEE_MODE_VERIFY, get_key_pair_bits(ctx->alg));
    if (ret != TEE_SUCCESS) {
        EMSG("Allocate operation failed\n");
        return ret;
    }

    // 设置验签密钥
    ret = TEE_SetOperationKey(ctx->verify_operation, ctx->key_pair);
    if (ret != TEE_SUCCESS) {
        EMSG("Set operation key failed\n");
        TEE_FreeTransientObject(ctx->key_pair);
        return ret;
    }

    IMSG("Generate Key Pair Successful\n");

    return TEE_SUCCESS;
}

// 生成摘要
static TEE_Result digest(struct sigh_and_verify_session *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    TEE_Result ret;
    struct sigh_and_verify_session *ctx = (struct sigh_and_verify_session *)sess_ctx; /* 会话上下文 */

    // 验证参数类型
    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    if (param_types != exp_param_type) {
        EMSG("param_types is not correct\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 此椭圆曲线算法在签名时自己会进行摘要, 不需要主动进行摘要
    if(ctx->alg == SIGH_VERIFY_ALG_ED25519) {
        EMSG("ED25519 algorithm does not need to digest\n")
        return TEE_ERROR_NOT_SUPPORTED;
    }

    // 释放之前的摘要操作句柄
    if(ctx->digest_operation != TEE_HANDLE_NULL)
        TEE_FreeOperation(ctx->digest_operation);

    // 申请摘要操作句柄
    ret = TEE_AllocateOperation(&ctx->digest_operation, get_tee_digest_alg(ctx->alg), TEE_MODE_DIGEST, 0);
    if(ret != TEE_SUCCESS) {
        EMSG("Allocate operation failed\n");
        return ret;
    }

    size_t out_size = params[1].memref.size; //输出大小
    size_t expected_size = (ctx->alg == SIGH_VERIFY_ALG_ECDSA_P256) ? 64 : 32; // 最少签名长度
    if(out_size < expected_size) {
        EMSG("Output buffer size is too small\n, expected_size = %d, out_size = %d", expected_size, out_size);
        return TEE_ERROR_SHORT_BUFFER;
    }

    // 计算摘要
    ret = TEE_DigestDoFinal(ctx->digest_operation, params[0].memref.buffer, params[0].memref.size,
                            params[1].memref.buffer, &out_size);
    if(ret != TEE_SUCCESS) {
        EMSG("Digest failed\n");
        return ret;
    }

    params[1].memref.size = out_size; //更新输出大小

    return TEE_SUCCESS;

    IMSG("Digest Successful\n");
}

// 签名
static TEE_Result sign(struct sigh_and_verify_session *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    TEE_Result ret;
    struct sigh_and_verify_session *ctx = (struct sigh_and_verify_session *)sess_ctx; /* 会话上下文 */

    // 验证参数类型
    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    if (param_types != exp_param_type) {
        EMSG("param_types is not correct\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    size_t out_size = params[1].memref.size; //输出大小

    // RSA 签名长度就等于密钥长度 这两个椭圆曲线签名长度都是64字节
    size_t expected_size = (ctx->alg < SIGH_VERIFY_ALG_ECDSA_P256) ? get_key_pair_bits(ctx->alg) / 8 : 64; // 签名长度
    if(out_size < expected_size) {
        EMSG("Output buffer size is too small\n, expected_size = %d, out_size = %d", expected_size, out_size);
        return TEE_ERROR_SHORT_BUFFER;
    }

    // 签名
    ret = TEE_AsymmetricSignDigest(ctx->sigh_operation, NULL, 0, params[0].memref.buffer, params[0].memref.size,
                                    params[1].memref.buffer, &out_size);
    if(ret != TEE_SUCCESS) {
        EMSG("Sign failed\n");
        return ret;
    }

    params[1].memref.size = out_size; //更新输出大小

    IMSG("Signature Successful\n");

    return TEE_SUCCESS;
}

// 验签
static TEE_Result verify(struct sigh_and_verify_session *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    TEE_Result ret;
    struct sigh_and_verify_session *ctx = (struct sigh_and_verify_session *)sess_ctx; /* 会话上下文 */

    // 对于 RSA 验证，param[0] 是摘要，param[1] 是签名
    // 对于 ECDSA/ED25519 验证，param[0] 是原始数据，param[1] 是签名
    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                         TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_type) {
        EMSG("param_types is not correct\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 验签
    ret = TEE_AsymmetricVerifyDigest(ctx->verify_operation, NULL, 0,
                                    params[0].memref.buffer, params[0].memref.size,
                                    params[1].memref.buffer, params[1].memref.size);
    if (ret != TEE_SUCCESS) {
        EMSG("Verify failed\n");
        return ret;
    }

    IMSG("Verify Successful\n");

    return TEE_SUCCESS;
}


/*******************************************************************************
 * Mandatory TA functions.
 ******************************************************************************/

TEE_Result TA_CreateEntryPoint(void)
{
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_type, TEE_Param params[4], void **sess_ctx)
{
    (void)param_type;
    (void)params;

    struct sigh_and_verify_session *ctx = TEE_Malloc(sizeof(struct sigh_and_verify_session), TEE_MALLOC_FILL_ZERO);

    *sess_ctx = ctx;

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    struct sigh_and_verify_session *ctx = (struct sigh_and_verify_session *)sess_ctx;

    free_handle(ctx);
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_type, TEE_Param params[4])
{
    switch(cmd) {
        case SIGH_VERIFY_CMD_GENERATE_KEYPAIR:
            return gen_key_pair(sess_ctx, param_type, params); // 生成密钥对

        case SIGH_VERIFY_CMD_DIGEST:
            return digest(sess_ctx, param_type, params); // 生成摘要

        case SIGH_VERIFY_CMD_SIGN:
            return sign(sess_ctx, param_type, params); // 签名

        case SIGH_VERIFY_CMD_VERIFY:
            return verify(sess_ctx, param_type, params); // 验签
        default:
            return TEE_ERROR_BAD_PARAMETERS;
    }
}
