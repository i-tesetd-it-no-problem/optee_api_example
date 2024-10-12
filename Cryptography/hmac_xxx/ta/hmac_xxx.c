#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "include/hmac_xxx.h"

struct hmac_xxx_ctx {
    TEE_OperationHandle operation;
    TEE_ObjectHandle key;
    uint8_t random_key[MAC_BITS / 8];
};

static TEE_Result generate_key(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result res;
    TEE_Attribute attr;
    struct hmac_xxx_ctx *ctx = (struct hmac_xxx_ctx *)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t out_size = params[0].memref.size;
    if (out_size < (MAC_BITS / 8)) {
        EMSG("key buffer is too small\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    res = TEE_IsAlgorithmSupported(USE_DIGEST_ALGORITHM, TEE_CRYPTO_ELEMENT_NONE);
    if (res != TEE_SUCCESS) {
        EMSG("the algorithm is not supported\n");
        return res;
    }

    if (ctx->key != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(ctx->key);
        ctx->key = TEE_HANDLE_NULL;
    }

    res = TEE_AllocateTransientObject(USE_KEY_TYPE, MAC_BITS, &ctx->key);
    if (res != TEE_SUCCESS) {
        EMSG("alloc key handle failed, res is 0x%x\n", res);
        return res;
    }

    TEE_GenerateRandom(ctx->random_key, MAC_BITS / 8);

    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, ctx->random_key, MAC_BITS / 8);
    res = TEE_PopulateTransientObject(ctx->key, &attr, 1);
    if(res != TEE_SUCCESS) {
        EMSG("generate key failed\n");
        goto err_free_key;
    }

    if (ctx->operation != TEE_HANDLE_NULL) {
        TEE_FreeOperation(ctx->operation);
        ctx->operation = TEE_HANDLE_NULL;
    }

    res = TEE_AllocateOperation(&ctx->operation, USE_DIGEST_ALGORITHM, TEE_MODE_MAC, MAC_BITS);
    if (res != TEE_SUCCESS) {
        EMSG("alloc operation failed, res is 0x%x\n", res);
        goto err_free_key;
    }

    res = TEE_SetOperationKey(ctx->operation, ctx->key);
    if (res != TEE_SUCCESS) {
        EMSG("set key to operation failed, res is 0x%x\n", res);
        goto err_free_operation;
    }
    
    TEE_MemMove(params[0].memref.buffer, ctx->random_key, MAC_BITS / 8);
    params[0].memref.size = MAC_BITS / 8;

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
    struct hmac_xxx_ctx *ctx = (struct hmac_xxx_ctx *)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t out_size = params[1].memref.size;
    if (out_size < (MAC_BITS / 8)) {
        EMSG("mac buffer is too small\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_MACInit(ctx->operation, NULL, 0);

    res = TEE_MACComputeFinal(ctx->operation, params[0].memref.buffer, params[0].memref.size,
                            params[1].memref.buffer, &out_size);
    if(res != TEE_SUCCESS) {
        EMSG("do_mac failed, res is 0x%x\n", res);
        return res;
    }

    params[1].memref.size = out_size;

    return TEE_SUCCESS;
}

static TEE_Result verify(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result res;
    struct hmac_xxx_ctx *ctx = (struct hmac_xxx_ctx *)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_MACInit(ctx->operation, NULL, 0);

    res = TEE_MACCompareFinal(ctx->operation, params[0].memref.buffer, params[0].memref.size,
                            params[1].memref.buffer, params[1].memref.size);
    if(res != TEE_SUCCESS) {
        EMSG("verify failed, res is 0x%x\n", res);
        return res;
    }

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

    struct hmac_xxx_ctx *ctx = TEE_Malloc(sizeof(struct hmac_xxx_ctx), TEE_MALLOC_FILL_ZERO);
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
    struct hmac_xxx_ctx *ctx = (struct hmac_xxx_ctx *)sess_ctx;

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
    case HMAC_XXX_GEN_KEY:
        return generate_key(sess_ctx, param_type, params);

    case HMAC_XXX_GEN_MAC:
        return do_mac(sess_ctx, param_type, params);

    case HMAC_XXX_VERIFY_MAC:
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
 
 * scp hmac_xxx/ta/d443b788-5283-498b-9940-5ee5f92f6a45.ta wenshuyu@192.168.1.6:/lib/optee_armtz
 * scp hmac_xxx/host/hmac_xxx wenshuyu@192.168.1.6:/usr/bin
 */

