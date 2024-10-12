#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "include/rsaes_pkcs1_v1_5.h"

struct rsaes_pkcs1_v1_5_ctx {
    TEE_OperationHandle operation;
    TEE_ObjectHandle keypair;
};

/**
 * keypair format：modulus + exponent
 */
static TEE_Result generate_key(void **sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    struct rsaes_pkcs1_v1_5_ctx *ctx = (struct rsaes_pkcs1_v1_5_ctx *)sess_ctx;
    TEE_Result res;

    (void)params;

    uint32_t exp_param_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_NONE, 
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE, 
        TEE_PARAM_TYPE_NONE
    );

    if (param_type != exp_param_type) {
        EMSG("bad parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // not supported ?
    // res = TEE_IsAlgorithmSupported(TEE_ALG_RSAES_PKCS1_V1_5, TEE_CRYPTO_ELEMENT_NONE);
    // if (res != TEE_SUCCESS) {
    //     EMSG("the algorithm is not supported\n");
    //     return res;
    // }

    if (ctx->keypair != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(ctx->keypair);
        ctx->keypair = TEE_HANDLE_NULL;
    }

    res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, KEYPAIR_BITS, &ctx->keypair);
    if (res != TEE_SUCCESS) {
        EMSG("alloc key pair faild\n");
        return res;
    }

    res = TEE_GenerateKey(ctx->keypair, KEYPAIR_BITS, NULL, 0);
    if (res != TEE_SUCCESS) {
        EMSG("generated key failed\n");
        goto err_free_key;
    }

    return TEE_SUCCESS;

err_free_key:
    if (ctx->keypair != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(ctx->keypair); 
        ctx->keypair = TEE_HANDLE_NULL;
    }
    return res;
}

static TEE_Result encrypt(void **sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    struct rsaes_pkcs1_v1_5_ctx *ctx = (struct rsaes_pkcs1_v1_5_ctx *)sess_ctx;
    TEE_Result res;
    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                                TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if(param_type != exp_param_type) {
        EMSG("param type is not correct\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t cipher_size = params[1].memref.size;
    if(cipher_size < KEYPAIR_SIZE) {
        EMSG("cipher buffer is too short\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if(ctx->operation != TEE_HANDLE_NULL)
        TEE_FreeOperation(ctx->operation);
    
    res = TEE_AllocateOperation(&ctx->operation, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_ENCRYPT, KEYPAIR_BITS);
    if(res != TEE_SUCCESS) {
        EMSG("alloc operation handle failed\n");
        return res;
    }

    res = TEE_SetOperationKey(ctx->operation, ctx->keypair);
    if(res != TEE_SUCCESS) {
        EMSG("set operation key failed\n");
        goto err_free_operation;
    }

    res = TEE_AsymmetricEncrypt(ctx->operation, NULL, 0,
                                    params[0].memref.buffer, params[0].memref.size,
                                    params[1].memref.buffer, &cipher_size);
    if(res != TEE_SUCCESS) {
        EMSG("encrypt failed\n");
        goto err_free_operation;
    }
    params[1].memref.size = cipher_size;

    return TEE_SUCCESS;

err_free_operation:
    if(ctx->operation != TEE_HANDLE_NULL) {
        TEE_FreeOperation(ctx->operation); 
        ctx->operation = TEE_HANDLE_NULL;
    }
        
    return res;
}

static TEE_Result decrypt(void **sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    struct rsaes_pkcs1_v1_5_ctx *ctx = (struct rsaes_pkcs1_v1_5_ctx *)sess_ctx;
    TEE_Result res;
    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                                TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if(param_type != exp_param_type) {
        EMSG("param type is not correct\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t plain_size = params[1].memref.size;
    if(plain_size < KEYPAIR_SIZE) {
        EMSG("plain buffer is too short\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if(ctx->operation != TEE_HANDLE_NULL)
        TEE_FreeOperation(ctx->operation);
    
    res = TEE_AllocateOperation(&ctx->operation, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_DECRYPT, KEYPAIR_BITS);
    if(res != TEE_SUCCESS) {
        EMSG("alloc operation handle failed\n");
        return res;
    }

    res = TEE_SetOperationKey(ctx->operation, ctx->keypair);
    if(res != TEE_SUCCESS) {
        EMSG("set operation key failed\n");
        goto err_free_operation;
    }

    res = TEE_AsymmetricDecrypt(ctx->operation, NULL, 0,
                                    params[0].memref.buffer, params[0].memref.size,
                                    params[1].memref.buffer, &plain_size);
    if(res != TEE_SUCCESS) {
        EMSG("decrypt failed\n");
        goto err_free_operation;
    }
    params[1].memref.size = plain_size;

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

    struct rsaes_pkcs1_v1_5_ctx *ctx = TEE_Malloc(sizeof(struct rsaes_pkcs1_v1_5_ctx),
                                            TEE_MALLOC_FILL_ZERO);
    if(!ctx) {
        EMSG("alloc context faild\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    *sess_ctx = ctx;

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    struct rsaes_pkcs1_v1_5_ctx *ctx = (struct rsaes_pkcs1_v1_5_ctx *)sess_ctx;

    if(ctx->operation != TEE_HANDLE_NULL)
        TEE_FreeOperation(ctx->operation);

    if(ctx->keypair != TEE_HANDLE_NULL)
        TEE_FreeTransientObject(ctx->keypair);

    TEE_Free(ctx);
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_type, TEE_Param params[4])
{
    switch(cmd) {
        case RSAES_PKCS1_V1_5_GEN_KEY:
            return generate_key(sess_ctx, param_type, params);

        case RSAES_PKCS1_V1_5_ENCRYPT:
            return encrypt(sess_ctx, param_type, params);

        case RSAES_PKCS1_V1_5_DECRYPT:
            return decrypt(sess_ctx, param_type, params);

        default:
            return TEE_ERROR_BAD_PARAMETERS;
    }
}

/**
 * @brief 配置到开发板指令

 * 注意: 开发本需提前配置好SSH环境, 
 * 根文件系统也需要支持OPTEE, buildroot自行配置

 * /lib/optee_armtz 是OPTEE寻找TA的默认地址
 * /usr/bin 让CA目标文件可以直接当作命令运行
 
 * scp rsaes_pkcs1_v1_5/ta/95a9449c-dce7-4dda-a1b7-37f7eb29ab91.ta wenshuyu@192.168.1.6:/lib/optee_armtz
 * scp rsaes_pkcs1_v1_5/host/rsaes_pkcs1_v1_5 wenshuyu@192.168.1.6:/usr/bin
 */

