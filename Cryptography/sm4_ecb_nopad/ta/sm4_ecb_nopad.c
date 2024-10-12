#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "include/sm4_ecb_nopad.h"

#define KEY_BYTES   (16)
#define KEY_BITS    (KEY_BYTES * 8)

#define BLOCK_SIZE  (16)
#define IS_NOT_MULTIPLE_OF_BLOCK_SIZE(_x) ((_x) & (BLOCK_SIZE - 1))

struct sm4_ecb_no_pad {
    TEE_OperationHandle operation;
    TEE_ObjectHandle key;
};

static TEE_Result generate_key(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result res;

    struct sm4_ecb_no_pad *ctx = (struct sm4_ecb_no_pad *)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
                                            TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if(param_type != exp_param_type) {
        EMSG("param type error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t out_size = params[0].memref.size;
    if(out_size < KEY_BYTES) {
        EMSG("key buffer is too small\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    res = TEE_IsAlgorithmSupported(TEE_ALG_SM4_ECB_NOPAD, TEE_CRYPTO_ELEMENT_NONE);
    if(res != TEE_SUCCESS) {
        EMSG("the algorithm is not supported\n");
        return res;
    }

    /* allow re-generate */
    if(ctx->key != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(ctx->key);
        ctx->key = TEE_HANDLE_NULL;
    }

    res = TEE_AllocateTransientObject(TEE_TYPE_SM4, KEY_BITS, &ctx->key);
    if(res != TEE_SUCCESS) {
        EMSG("alloc key handle failed, res is 0x%x\n", res);
        return res;
    }

    res = TEE_GenerateKey(ctx->key, KEY_BITS, NULL, 0);
    if(res != TEE_SUCCESS) {
        EMSG("generate key failed, res is 0x%x\n", res);
        goto err_free_key;
    }

    res = TEE_GetObjectBufferAttribute(ctx->key, TEE_ATTR_SECRET_VALUE,
                                        params[0].memref.buffer, &out_size);
    if(res != TEE_SUCCESS) {
        EMSG("get key failed, res is 0x%x\n", res);
        goto err_free_key;
    }
    
    params[0].memref.size = out_size;

    return TEE_SUCCESS;

err_free_key:
    if(ctx->key != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(ctx->key);
        ctx->key = TEE_HANDLE_NULL;
    }

    return res;
}

static TEE_Result encrypt(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result res;

    struct sm4_ecb_no_pad *ctx = (struct sm4_ecb_no_pad *)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                            TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if(param_type != exp_param_type) {
        EMSG("param type error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t in_size = params[0].memref.size;

    if(IS_NOT_MULTIPLE_OF_BLOCK_SIZE(in_size)) {
        EMSG("the plain text size is not correct\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t out_size = params[1].memref.size;
    if(out_size < in_size) {
        EMSG("cipher text buffer is too small\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if(ctx->operation != TEE_HANDLE_NULL) {
        TEE_FreeOperation(ctx->operation);
        ctx->operation = TEE_HANDLE_NULL;
    }

    res = TEE_AllocateOperation(&ctx->operation, TEE_ALG_SM4_ECB_NOPAD, TEE_MODE_ENCRYPT, KEY_BITS);
    if(res != TEE_SUCCESS) {
        EMSG("alloc operation failed, res is 0x%x\n", res);
        return res;
    }

    res = TEE_SetOperationKey(ctx->operation, ctx->key);
    if(res != TEE_SUCCESS) {
        EMSG("set key to operation failed, res is 0x%x\n", res);
        goto err_free_operation;
    }

    TEE_CipherInit(ctx->operation, NULL, 0);
    
    res = TEE_CipherDoFinal(ctx->operation, params[0].memref.buffer, params[0].memref.size,
                            params[1].memref.buffer, &out_size);
    if(res != TEE_SUCCESS) {
        EMSG("encrypt failed, res is 0x%x\n", res);
        goto err_free_operation;
    }

    params[1].memref.size = out_size;

    return TEE_SUCCESS;

err_free_operation:
    if(ctx->operation != TEE_HANDLE_NULL) {
        TEE_FreeOperation(ctx->operation);
        ctx->operation = TEE_HANDLE_NULL;
    }

    return res;
}

static TEE_Result decrypt(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result res;

    struct sm4_ecb_no_pad *ctx = (struct sm4_ecb_no_pad *)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                            TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if(param_type != exp_param_type) {
        EMSG("param type error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t in_size = params[0].memref.size;
    uint32_t out_size = params[1].memref.size;
    if(out_size < in_size) {
        EMSG("plain text buffer is too small\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if(ctx->operation != TEE_HANDLE_NULL) {
        TEE_FreeOperation(ctx->operation);
        ctx->operation = TEE_HANDLE_NULL;
    }

    res = TEE_AllocateOperation(&ctx->operation, TEE_ALG_SM4_ECB_NOPAD, TEE_MODE_DECRYPT, KEY_BITS);
    if(res != TEE_SUCCESS) {
        EMSG("alloc operation failed, res is 0x%x\n", res);
        return res;
    }

    res = TEE_SetOperationKey(ctx->operation, ctx->key);
    if(res != TEE_SUCCESS) {
        EMSG("set key to operation failed, res is 0x%x\n", res);
        goto err_free_operation;
    }

    TEE_CipherInit(ctx->operation, NULL, 0);
    
    res = TEE_CipherDoFinal(ctx->operation, params[0].memref.buffer, params[0].memref.size,
                            params[1].memref.buffer, &out_size);
    if(res != TEE_SUCCESS) {
        EMSG("decrypt failed, res is 0x%x\n", res);
        goto err_free_operation;
    }

    params[1].memref.size = out_size;
    
    return TEE_SUCCESS;

err_free_operation:
    if(ctx->operation != TEE_HANDLE_NULL) {
        TEE_FreeOperation(ctx->operation);
        ctx->operation = TEE_HANDLE_NULL;
    }

    return res;
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

    struct sm4_ecb_no_pad *ctx = TEE_Malloc(sizeof(struct sm4_ecb_no_pad), TEE_MALLOC_FILL_ZERO);
    if(!ctx) {
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
    struct sm4_ecb_no_pad *ctx = (struct sm4_ecb_no_pad *)sess_ctx;

    if(ctx->operation != TEE_HANDLE_NULL) {
        TEE_FreeOperation(ctx->operation);
        ctx->operation = TEE_HANDLE_NULL;
    }
        
    if(ctx->key != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(ctx->key);
        ctx->key = TEE_HANDLE_NULL;
    }

    TEE_Free(ctx);
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_type, TEE_Param params[4])
{
    switch(cmd) {
        case TA_SM4_CBC_NOPAD_GEN_KEY:
            return generate_key(sess_ctx, param_type, params);

        case TA_SM4_ECB_NOPAD_ENCRYPT:
            return encrypt(sess_ctx, param_type, params);

        case TA_SM4_ECB_NOPAD_DECRYPT:
            return decrypt(sess_ctx, param_type, params);

        default:
            EMSG("unsurpported command\n");
            return TEE_ERROR_BAD_PARAMETERS;
    }
}

/**
 * @brief 配置到开发板指令

 * 注意: 开发本需提前配置好SSH环境, 
 * 根文件系统也需要支持OPTEE, buildroot自行配置

 * /lib/optee_armtz 是OPTEE寻找TA的默认地址
 * /usr/bin 让CA目标文件可以直接当作命令运行
 
 * scp sm4_ecb_nopad/ta/86f19caf-bccc-4df4-99af-50c92db0be29.ta wenshuyu@192.168.1.6:/lib/optee_armtz
 * scp sm4_ecb_nopad/host/sm4_ecb_nopad wenshuyu@192.168.1.6:/usr/bin
 */

