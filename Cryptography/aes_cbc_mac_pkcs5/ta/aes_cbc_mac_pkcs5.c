#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "include/aes_cbc_mac_pkcs5.h"

#define KEY_BYTES   (32)
#define KEY_BITS    (KEY_BYTES * 8)

#define BLOCK_SIZE  (16)
#define IS_NOT_MULTIPLE_OF_BLOCK_SIZE(_x) ((_x) & (BLOCK_SIZE - 1))

struct aes_cbc_mac_pkcs5 {
    TEE_OperationHandle operation;
    TEE_ObjectHandle key;
};

static TEE_Result generate_key(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result res;

    struct aes_cbc_mac_pkcs5 *ctx = (struct aes_cbc_mac_pkcs5 *)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t out_size = params[0].memref.size;
    if (out_size < KEY_BYTES) {
        EMSG("key buffer is too small\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    res = TEE_IsAlgorithmSupported(TEE_ALG_AES_CBC_MAC_PKCS5, TEE_CRYPTO_ELEMENT_NONE);
    if (res != TEE_SUCCESS) {
        EMSG("the algorithm is not supported\n");
        return res;
    }

    if (ctx->key != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(ctx->key);
        ctx->key = TEE_HANDLE_NULL;
    }

    res = TEE_AllocateTransientObject(TEE_TYPE_AES, KEY_BITS, &ctx->key);
    if (res != TEE_SUCCESS) {
        EMSG("alloc key handle failed, res is 0x%x\n", res);
        return res;
    }

    res = TEE_GenerateKey(ctx->key, KEY_BITS, NULL, 0);
    if (res != TEE_SUCCESS) {
        EMSG("generate key failed, res is 0x%x\n", res);
        goto err_free_key;
    }

    if (ctx->operation != TEE_HANDLE_NULL) {
        TEE_FreeOperation(ctx->operation);
        ctx->operation = TEE_HANDLE_NULL;
    }

    res = TEE_AllocateOperation(&ctx->operation, TEE_ALG_AES_CBC_MAC_PKCS5, TEE_MODE_MAC, KEY_BITS);
    if (res != TEE_SUCCESS) {
        EMSG("alloc operation failed, res is 0x%x\n", res);
        goto err_free_key;
    }

    res = TEE_SetOperationKey(ctx->operation, ctx->key);
    if (res != TEE_SUCCESS) {
        EMSG("set key to operation failed, res is 0x%x\n", res);
        goto err_free_operation;
    }

    res = TEE_GetObjectBufferAttribute(ctx->key, TEE_ATTR_SECRET_VALUE,
                                       params[0].memref.buffer, &out_size);
    if (res != TEE_SUCCESS) {
        EMSG("get key failed, res is 0x%x\n", res);
        goto err_free_operation;
    }

    params[0].memref.size = out_size;

    return TEE_SUCCESS;

err_free_operation:
    if (ctx->operation != TEE_HANDLE_NULL) {
        TEE_FreeOperation(ctx->operation);
        ctx->operation = TEE_HANDLE_NULL;
    }

err_free_key:
    if (ctx->key != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(ctx->key);
        ctx->key = TEE_HANDLE_NULL;
    }

    return res;
}

static TEE_Result do_mac(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result res;
    struct aes_cbc_mac_pkcs5 *ctx = (struct aes_cbc_mac_pkcs5 *)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t out_size = params[1].memref.size;
    if (out_size < BLOCK_SIZE) {
        EMSG("MAC buffer is too small\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_MACInit(ctx->operation, NULL, 0);

    res = TEE_MACComputeFinal(ctx->operation, params[0].memref.buffer, params[0].memref.size,
                              params[1].memref.buffer, &out_size);
    if (res != TEE_SUCCESS) {
        EMSG("MAC calculate failed, res is 0x%x\n", res);
        return res;
    }

    params[1].memref.size = out_size;

    return TEE_SUCCESS;
}

static TEE_Result verify(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result res;
    struct aes_cbc_mac_pkcs5 *ctx = (struct aes_cbc_mac_pkcs5 *)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_MACInit(ctx->operation, NULL, 0);

    res = TEE_MACCompareFinal(ctx->operation, params[0].memref.buffer, params[0].memref.size,
                              params[1].memref.buffer, params[1].memref.size);
    if (res != TEE_SUCCESS) {
        EMSG("MAC compare failed, res is 0x%x\n", res);
        return res;
    }

    IMSG("verify mac successful\n");

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

    struct aes_cbc_mac_pkcs5 *ctx = TEE_Malloc(sizeof(struct aes_cbc_mac_pkcs5), TEE_MALLOC_FILL_ZERO);
    if (!ctx) {
        EMSG("TEE_Malloc Failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ctx->operation = TEE_HANDLE_NULL;
    ctx->key = TEE_HANDLE_NULL;

    *sess_ctx = ctx;

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    struct aes_cbc_mac_pkcs5 *ctx = (struct aes_cbc_mac_pkcs5 *)sess_ctx;

    if (ctx->operation != TEE_HANDLE_NULL) {
        TEE_FreeOperation(ctx->operation);
        ctx->operation = TEE_HANDLE_NULL;
    }

    if (ctx->key != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(ctx->key);
        ctx->key = TEE_HANDLE_NULL;
    }

    TEE_Free(ctx);
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_type, TEE_Param params[4])
{
    switch (cmd) {
    case AES_CBC_MAC_PKCS5_GEN_KEY:
        return generate_key(sess_ctx, param_type, params);

    case AES_CBC_MAC_PKCS5_GEN_MAC:
        return do_mac(sess_ctx, param_type, params);

    case AES_CBC_MAC_PKCS5_VERIFY:
        return verify(sess_ctx, param_type, params);

    default:
        EMSG("unsupported command\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
}

/**
 * @brief 配置到开发板指令

 * 注意: 开发本需提前配置好SSH环境, 
 * 根文件系统也需要支持OPTEE, buildroot自行配置

 * /lib/optee_armtz 是OPTEE寻找TA的默认地址
 * /usr/bin 让CA目标文件可以直接当作命令运行
 
 * scp aes_cbc_mac_pkcs5/ta/827066b8-e173-44a4-9d46-495d08ec5aba.ta wenshuyu@192.168.1.6:/lib/optee_armtz
 * scp aes_cbc_mac_pkcs5/host/aes_cbc_mac_pkcs5 wenshuyu@192.168.1.6:/usr/bin
 */

