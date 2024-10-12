#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "dsa_sha256.h"

struct dsa_sha256_ctx {
    TEE_OperationHandle operation;
    TEE_ObjectHandle keypair;

    uint8_t tee_attr_dsa_prime[DSA_PRIME_SIZE];
    uint8_t tee_attr_dsa_subprime[DSA_SUBPRIME_SIZE];
    uint8_t tee_attr_dsa_base[DSA_BASE_SIZE];
    uint8_t tee_attr_dsa_public_value[DSA_PUB_VALUE_SIZE];
    uint8_t tee_attr_dsa_private_value[DSA_PRIV_VALUE_SIZE];
};

static TEE_Result set_key0(void **sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    struct dsa_sha256_ctx *ctx = (struct dsa_sha256_ctx *)sess_ctx;
    TEE_Result res;

    uint32_t exp_param_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, 
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT, 
        TEE_PARAM_TYPE_NONE
    );

    if (param_type != exp_param_type) {
        EMSG("bad parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    res = TEE_IsAlgorithmSupported(USE_DSA_ALGORITHM, TEE_CRYPTO_ELEMENT_NONE);
    if (res != TEE_SUCCESS) {
        EMSG("the algorithm is not supported\n");
        return res;
    }

    if (ctx->keypair != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(ctx->keypair);
        ctx->keypair = TEE_HANDLE_NULL;
    }

    res = TEE_AllocateTransientObject(TEE_TYPE_DSA_KEYPAIR, KEYPAIR_BITS, &ctx->keypair);
    if (res != TEE_SUCCESS) {
        EMSG("alloc key pair failed\n");
        return res;
    }

    if (params[0].memref.size != DSA_PRIME_SIZE ||
        params[1].memref.size != DSA_SUBPRIME_SIZE ||
        params[2].memref.size != DSA_BASE_SIZE) {
        EMSG("incorrect DSA parameter sizes\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_MemMove(ctx->tee_attr_dsa_prime, params[0].memref.buffer, params[0].memref.size);
    TEE_MemMove(ctx->tee_attr_dsa_subprime, params[1].memref.buffer, params[1].memref.size);
    TEE_MemMove(ctx->tee_attr_dsa_base, params[2].memref.buffer, params[2].memref.size);
    return TEE_SUCCESS;
}

static TEE_Result set_key1(void **sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    struct dsa_sha256_ctx *ctx = (struct dsa_sha256_ctx *)sess_ctx;
    TEE_Attribute dsa_attrs[DSA_COMPONENTS_MAX] = {0};
    TEE_Result res;

    uint32_t exp_param_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, 
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE, 
        TEE_PARAM_TYPE_NONE
    );

    if (param_type != exp_param_type) {
        EMSG("bad parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[0].memref.size != DSA_PUB_VALUE_SIZE ||
        params[1].memref.size != DSA_PRIV_VALUE_SIZE) {
        EMSG("incorrect public/private key sizes\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_MemMove(ctx->tee_attr_dsa_public_value, params[0].memref.buffer, params[0].memref.size);
    TEE_MemMove(ctx->tee_attr_dsa_private_value, params[1].memref.buffer, params[1].memref.size);

    TEE_InitRefAttribute(&dsa_attrs[DSA_PRIME], TEE_ATTR_DSA_PRIME, ctx->tee_attr_dsa_prime, DSA_PRIME_SIZE);
    TEE_InitRefAttribute(&dsa_attrs[DSA_SUBPRIME], TEE_ATTR_DSA_SUBPRIME, ctx->tee_attr_dsa_subprime, DSA_SUBPRIME_SIZE);
    TEE_InitRefAttribute(&dsa_attrs[DSA_BASE], TEE_ATTR_DSA_BASE, ctx->tee_attr_dsa_base, DSA_BASE_SIZE);
    TEE_InitRefAttribute(&dsa_attrs[DSA_PUB_VALUE], TEE_ATTR_DSA_PUBLIC_VALUE, ctx->tee_attr_dsa_public_value, DSA_PUB_VALUE_SIZE);
    TEE_InitRefAttribute(&dsa_attrs[DSA_PRIV_VALUE], TEE_ATTR_DSA_PRIVATE_VALUE, ctx->tee_attr_dsa_private_value, DSA_PRIV_VALUE_SIZE);

    res = TEE_PopulateTransientObject(ctx->keypair, dsa_attrs, DSA_COMPONENTS_MAX);
    if (res != TEE_SUCCESS) {
        EMSG("set key pair failed\n");
        return res;
    }

    return TEE_SUCCESS;
}


static TEE_Result digest(void **sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    struct dsa_sha256_ctx *ctx = (struct dsa_sha256_ctx *)sess_ctx;
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
    
    res = TEE_AllocateOperation(&ctx->operation, USE_DIGEST_ALGORITHM, TEE_MODE_DIGEST, 0); // digest does not require key size
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
    struct dsa_sha256_ctx *ctx = (struct dsa_sha256_ctx *)sess_ctx;
    TEE_Result res;
    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                                TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if(param_type != exp_param_type) {
        EMSG("param type is not correct\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[1].memref.size < SIGNATURE_SIZE) {
        EMSG("signature buffer is too short\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t signature_size = params[1].memref.size;

    if(ctx->operation != TEE_HANDLE_NULL)
        TEE_FreeOperation(ctx->operation);
    
    res = TEE_AllocateOperation(&ctx->operation, USE_DSA_ALGORITHM, TEE_MODE_SIGN, KEYPAIR_BITS);
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
    struct dsa_sha256_ctx *ctx = (struct dsa_sha256_ctx *)sess_ctx;
    TEE_Result res;
    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                                TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if(param_type != exp_param_type) {
        EMSG("param type is not correct\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if(ctx->operation != TEE_HANDLE_NULL)
        TEE_FreeOperation(ctx->operation);
    
    res = TEE_AllocateOperation(&ctx->operation, USE_DSA_ALGORITHM, TEE_MODE_VERIFY, KEYPAIR_BITS);
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

    IMSG("verify signature success\n");

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

    struct dsa_sha256_ctx *ctx = TEE_Malloc(sizeof(struct dsa_sha256_ctx),
                                            TEE_MALLOC_FILL_ZERO);
    if(!ctx) {
        EMSG("alloc context failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    *sess_ctx = ctx;

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    struct dsa_sha256_ctx *ctx = (struct dsa_sha256_ctx *)sess_ctx;

    if(ctx->operation != TEE_HANDLE_NULL)
        TEE_FreeOperation(ctx->operation);

    if(ctx->keypair != TEE_HANDLE_NULL)
        TEE_FreeTransientObject(ctx->keypair);

    TEE_Free(ctx);
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_type, TEE_Param params[4])
{
    switch(cmd) {
        case DSA_SHA256_SET_KEY_0:
            return set_key0(sess_ctx, param_type, params);
        
        case DSA_SHA256_SET_KEY_1:
            return set_key1(sess_ctx, param_type, params);

        case DSA_SHA256_DIGEST:
            return digest(sess_ctx, param_type, params);

        case DSA_SHA256_SIGN:
            return sign(sess_ctx, param_type, params);

        case DSA_SHA256_VERIFY:
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
 
 * scp dsa_sha256/ta/9db4bf13-7706-4ef9-8ac3-e38b820b03d0.ta wenshuyu@192.168.1.6:/lib/optee_armtz
 * scp dsa_sha256/host/dsa_sha256 wenshuyu@192.168.1.6:/usr/bin
 */