#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "include/ecdsa_xxx.h"

struct ecdsa_xxx_ctx {
    TEE_OperationHandle operation;
    TEE_ObjectHandle keypair;
};

static TEE_Result generate_key(void **sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    struct ecdsa_xxx_ctx *ctx = (struct ecdsa_xxx_ctx *)sess_ctx;
    TEE_Attribute attr;
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

    res = TEE_IsAlgorithmSupported(USE_ECDSA_ALGORITHM, USE_ELEMENT);
    if (res != TEE_SUCCESS) {
        EMSG("the algorithm is not supported\n");
        return res;
    }

    if (ctx->keypair != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(ctx->keypair);
        ctx->keypair = TEE_HANDLE_NULL;
    }

    res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, KEYPAIR_BITS, &ctx->keypair);
    if (res != TEE_SUCCESS) {
        EMSG("alloc key pair faild\n");
        return res;
    }

    TEE_InitValueAttribute(&attr, TEE_ATTR_ECC_CURVE, USE_ELEMENT, 0);

    res = TEE_GenerateKey(ctx->keypair, KEYPAIR_BITS, &attr, 1);
    if (res != TEE_SUCCESS) {
        EMSG("generated key failed\n");
        goto err_free_keypair;
    }

    IMSG("\nKey pair generated successfully\n\n");

    return TEE_SUCCESS;

err_free_keypair:
    if (ctx->keypair != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(ctx->keypair); 
        ctx->keypair = TEE_HANDLE_NULL;
    }
    return res;
}

static TEE_Result digest(void **sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    struct ecdsa_xxx_ctx *ctx = (struct ecdsa_xxx_ctx *)sess_ctx;
    TEE_Result res;
    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                                TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if(param_type != exp_param_type) {
        EMSG("param type is not correct\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[1].memref.size < (DIGEST_BITS / 8)) {
        EMSG("digest buffer is too short\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t digest_size = params[1].memref.size;

    if(ctx->operation != TEE_HANDLE_NULL)
        TEE_FreeOperation(ctx->operation);
    
    res = TEE_AllocateOperation(&ctx->operation, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if(res != TEE_SUCCESS) {
        EMSG("alloc operation handle failed\n");
        return res;
    }

    res = TEE_DigestDoFinal(ctx->operation, params[0].memref.buffer, params[0].memref.size,
                            params[1].memref.buffer, &digest_size);
    if(res != TEE_SUCCESS) {
        TEE_FreeOperation(ctx->operation);
        ctx->operation = TEE_HANDLE_NULL;
        EMSG("digest failed\n");
        return res;
    }

    params[1].memref.size = digest_size;
    return TEE_SUCCESS;
}

static TEE_Result sign(void **sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    struct ecdsa_xxx_ctx *ctx = (struct ecdsa_xxx_ctx *)sess_ctx;
    TEE_Result res;
    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                                TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if(param_type != exp_param_type) {
        EMSG("param type is not correct\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t signature_size = params[1].memref.size;
    if(signature_size < KEYPAIR_SIZE * 2) {
        EMSG("signature buffer is too short\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if(ctx->operation != TEE_HANDLE_NULL)
        TEE_FreeOperation(ctx->operation);
    
    res = TEE_AllocateOperation(&ctx->operation, USE_ECDSA_ALGORITHM, TEE_MODE_SIGN, KEYPAIR_BITS);
    if(res != TEE_SUCCESS) {
        EMSG("alloc operation handle failed\n");
        return res;
    }

    res = TEE_SetOperationKey(ctx->operation, ctx->keypair);
    if(res != TEE_SUCCESS) {
        EMSG("set operation key failed\n");
        goto err_free_operation;
    }

    res = TEE_AsymmetricSignDigest(ctx->operation, NULL, 0,
                                    params[0].memref.buffer, params[0].memref.size,
                                    params[1].memref.buffer, &signature_size);
    if(res != TEE_SUCCESS) {
        EMSG("sign failed\n");
        goto err_free_operation;
    }
    params[1].memref.size = signature_size;

    return TEE_SUCCESS;

err_free_operation:
    if(ctx->operation != TEE_HANDLE_NULL) {
        TEE_FreeOperation(ctx->operation); 
        ctx->operation = TEE_HANDLE_NULL;
    }
        
    return res;
}

static TEE_Result verify(void **sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    struct ecdsa_xxx_ctx *ctx = (struct ecdsa_xxx_ctx *)sess_ctx;
    TEE_Result res;
    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                                TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if(param_type != exp_param_type) {
        EMSG("param type is not correct\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if(ctx->operation != TEE_HANDLE_NULL)
        TEE_FreeOperation(ctx->operation);
    
    res = TEE_AllocateOperation(&ctx->operation, USE_ECDSA_ALGORITHM, TEE_MODE_VERIFY, KEYPAIR_BITS);
    if(res != TEE_SUCCESS) {
        EMSG("alloc operation handle failed\n");
        return res;
    }

    res = TEE_SetOperationKey(ctx->operation, ctx->keypair);
    if(res != TEE_SUCCESS) {
        EMSG("set operation key failed\n");
        goto err_free_operation;
    }

    res = TEE_AsymmetricVerifyDigest(ctx->operation, NULL, 0,
                                    params[0].memref.buffer, params[0].memref.size,
                                    params[1].memref.buffer, params[1].memref.size);
    if(res != TEE_SUCCESS) {
        EMSG("verify failed\n");
        goto err_free_operation;
    }

    IMSG("verify successful\n");

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

    struct ecdsa_xxx_ctx *ctx = TEE_Malloc(sizeof(struct ecdsa_xxx_ctx),
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
    struct ecdsa_xxx_ctx *ctx = (struct ecdsa_xxx_ctx *)sess_ctx;

    if(ctx->operation != TEE_HANDLE_NULL)
        TEE_FreeOperation(ctx->operation);

    if(ctx->keypair != TEE_HANDLE_NULL)
        TEE_FreeTransientObject(ctx->keypair);

    TEE_Free(ctx);
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_type, TEE_Param params[4])
{
    switch(cmd) {
        case ECDSA_XXX_GEN_KEY:
            return generate_key(sess_ctx, param_type, params);

        case ECDSA_XXX_DIGEST:
            return digest(sess_ctx, param_type, params);

        case ECDSA_XXX_SIGN:
            return sign(sess_ctx, param_type, params);

        case ECDSA_XXX_VERIFY:
            return verify(sess_ctx, param_type, params);

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
 
 * scp ecdsa_xxx/ta/ad3fae37-3956-48fe-86b3-a6f9135a87cb.ta wenshuyu@192.168.1.6:/lib/optee_armtz
 * scp ecdsa_xxx/host/ecdsa_xxx wenshuyu@192.168.1.6:/usr/bin
 */

