#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "include/dh_basic.h"

// 根据GP规范 TEE_TYPE_GENERIC_SECRET 的类型必须是8的倍数
static int align_to_8(int num) {
    if (num % 8 == 0) 
        return num;
    else 
        return (num + 8 - (num % 8));
}

struct dh_basic_ctx {
    TEE_OperationHandle operation;
    TEE_ObjectHandle keypair;
    TEE_ObjectHandle shared_key;
    TEE_ObjectHandle aes_key; 
};

static TEE_Result generate_keypair(struct dh_basic_ctx* sess_ctx, uint32_t param_type, TEE_Param params[4]) {
    TEE_Result res;
    TEE_Attribute attrs[2];
    struct dh_basic_ctx *ctx = (struct dh_basic_ctx *)sess_ctx;
    uint32_t exp_param_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_OUTPUT, 
        TEE_PARAM_TYPE_MEMREF_INPUT,  
        TEE_PARAM_TYPE_MEMREF_INPUT,  
        TEE_PARAM_TYPE_NONE);

    if (param_type != exp_param_type) {
        EMSG("Parameter types mismatch\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    void *dh_prime = params[1].memref.buffer;
    size_t dh_prime_len = params[1].memref.size;

    void *dh_base = params[2].memref.buffer;
    size_t dh_base_len = params[2].memref.size;

    uint32_t out_size = params[0].memref.size;
    if (out_size < KEYPAIR_BYTES) {
        EMSG("Public key buffer is too small\n");
        return TEE_ERROR_SHORT_BUFFER;
    }
 
    if (ctx->keypair != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(ctx->keypair);
        ctx->keypair = TEE_HANDLE_NULL;
    }

    res = TEE_AllocateTransientObject(TEE_TYPE_DH_KEYPAIR, KEYPAIR_BITS, &ctx->keypair);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to allocate transient object, res = 0x%x\n", res);
        return res;
    }
    
    TEE_InitRefAttribute(&attrs[0], TEE_ATTR_DH_PRIME, dh_prime, dh_prime_len);
    TEE_InitRefAttribute(&attrs[1], TEE_ATTR_DH_BASE, dh_base, dh_base_len);

    res = TEE_GenerateKey(ctx->keypair, KEYPAIR_BITS, attrs, 2);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to generate keypair, res = 0x%x\n", res);
        goto err_free_keypair;
    }

    res = TEE_GetObjectBufferAttribute(ctx->keypair, TEE_ATTR_DH_PUBLIC_VALUE, params[0].memref.buffer, &out_size);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to get public value, res = 0x%x\n", res);
        goto err_free_keypair;
    }

    params[0].memref.size = out_size;

    IMSG("\nKey pair generated successfully\n\n");

    return TEE_SUCCESS;

err_free_keypair:
    if (ctx->keypair) {
        TEE_FreeTransientObject(ctx->keypair);
        ctx->keypair = TEE_HANDLE_NULL;
    }

    return res;
}

static TEE_Result generate_shared_key(struct dh_basic_ctx* sess_ctx, uint32_t param_type, TEE_Param params[4]) {
    TEE_Result res;
    TEE_Attribute attr;
    struct dh_basic_ctx *ctx = (struct dh_basic_ctx *)sess_ctx;
    uint32_t exp_param_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, 
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    if (param_type != exp_param_type) {
        EMSG("Parameter types mismatch\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (ctx->operation != TEE_HANDLE_NULL) {
        TEE_FreeOperation(ctx->operation);
        ctx->operation = TEE_HANDLE_NULL;
    }

    
    res = TEE_AllocateOperation(&ctx->operation, TEE_ALG_DH_DERIVE_SHARED_SECRET, TEE_MODE_DERIVE, KEYPAIR_BITS);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to allocate operation, res = 0x%x\n", res);
        return res;
    }

    res = TEE_SetOperationKey(ctx->operation, ctx->keypair);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to set operation key, res = 0x%x\n", res);
        goto err_free_operation;
    }

    if (ctx->shared_key != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(ctx->shared_key);
        ctx->shared_key = TEE_HANDLE_NULL;
    }

    res = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET, align_to_8(KEYPAIR_BITS), &ctx->shared_key);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to allocate shared key object, res = 0x%x\n", res);
        goto err_free_operation;
    }

    TEE_InitRefAttribute(&attr, TEE_ATTR_DH_PUBLIC_VALUE, params[0].memref.buffer, params[0].memref.size);

    TEE_DeriveKey(ctx->operation, &attr, 1, ctx->shared_key);
    
    uint8_t shared_secret[KEYPAIR_BYTES];
    size_t shared_secret_len = sizeof(shared_secret);
    res = TEE_GetObjectBufferAttribute(ctx->shared_key, TEE_ATTR_SECRET_VALUE, shared_secret, &shared_secret_len);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to get shared secret, res = 0x%x\n", res);
        goto err_free_operation;
    }

    TEE_OperationHandle hash_op = TEE_HANDLE_NULL;
    uint8_t aes_key[AES_SECRET_BITS / 8]; 
    uint32_t aes_key_len = sizeof(aes_key);

    res = TEE_AllocateOperation(&hash_op, USE_ALG_AES_HASH, TEE_MODE_DIGEST, 0);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to allocate hash operation, res = 0x%x\n", res);
        goto err_free_operation;
    }

    res = TEE_DigestDoFinal(hash_op, shared_secret, shared_secret_len, aes_key, &aes_key_len);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to compute hash, res = 0x%x\n", res);
        TEE_FreeOperation(hash_op);
        goto err_free_operation;
    }

    TEE_FreeOperation(hash_op);

    if (ctx->aes_key != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(ctx->aes_key);
        ctx->aes_key = TEE_HANDLE_NULL;
    }

    res = TEE_AllocateTransientObject(TEE_TYPE_AES, AES_SECRET_BITS, &ctx->aes_key);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to allocate AES key object, res = 0x%x\n", res);
        goto err_free_operation;
    }

    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, aes_key, aes_key_len);
    res = TEE_PopulateTransientObject(ctx->aes_key, &attr, 1);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to populate AES key object, res = 0x%x\n", res);
        TEE_FreeTransientObject(ctx->aes_key);
        ctx->aes_key = TEE_HANDLE_NULL;
        goto err_free_operation;
    }

    IMSG("\nAES key derived successfully\n\n");

    return TEE_SUCCESS;

err_free_operation:
    if (ctx->operation) {
        TEE_FreeOperation(ctx->operation);
        ctx->operation = TEE_HANDLE_NULL;
    }
    return res;
}

static TEE_Result decrypt(struct dh_basic_ctx* sess_ctx, uint32_t param_type, TEE_Param params[4]) {
    TEE_Result res;
    struct dh_basic_ctx *ctx = (struct dh_basic_ctx *)sess_ctx;
    uint32_t exp_param_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, 
        TEE_PARAM_TYPE_MEMREF_INPUT, 
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    if (param_type != exp_param_type) {
        EMSG("Parameter types mismatch\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (ctx->operation != TEE_HANDLE_NULL) {
        TEE_FreeOperation(ctx->operation);
        ctx->operation = TEE_HANDLE_NULL;
    }

    res = TEE_AllocateOperation(&ctx->operation, TEE_ALG_AES_CTR, TEE_MODE_DECRYPT, 256);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to allocate operation, res = 0x%x\n", res);
        return res;
    }

    res = TEE_SetOperationKey(ctx->operation, ctx->aes_key);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to set operation key, res = 0x%x\n", res);
        goto err_free_operation;
    }

    TEE_CipherInit(ctx->operation, params[1].memref.buffer, params[1].memref.size);

    uint8_t plain_buf[256];
    uint32_t plain_len = sizeof(plain_buf);
    res = TEE_CipherUpdate(ctx->operation, params[0].memref.buffer, params[0].memref.size,
                           plain_buf, &plain_len);
    if (res != TEE_SUCCESS) {
        EMSG("Cipher update failed, res = 0x%x\n", res);
        goto err_free_operation;
    }

    printf("\nthe Bob's message is:\n");
    for (uint32_t i = 0; i < plain_len; i++) {
        printf("%c", plain_buf[i]);
    }
    printf("\n\n");

    return TEE_SUCCESS;

err_free_operation:
    if (ctx->operation != TEE_HANDLE_NULL) {
        TEE_FreeOperation(ctx->operation);
        ctx->operation = TEE_HANDLE_NULL;
    }

    return res;
}

/*******************************************************************************
 * Mandatory TA functions.
 ******************************************************************************/

TEE_Result TA_CreateEntryPoint(void) {
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
    
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_type, TEE_Param params[4], void **sess_ctx) {
    (void)param_type;
    (void)params;

    struct dh_basic_ctx* ctx = TEE_Malloc(sizeof(struct dh_basic_ctx), TEE_MALLOC_FILL_ZERO);
    if (!ctx) {
        EMSG("Memory allocation failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    *sess_ctx = ctx;

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx) {
    struct dh_basic_ctx* ctx = (struct dh_basic_ctx *)sess_ctx;

    if (ctx->operation) {
        TEE_FreeOperation(ctx->operation);
        ctx->operation = TEE_HANDLE_NULL;
    }

    if (ctx->keypair) {
        TEE_FreeTransientObject(ctx->keypair);
        ctx->keypair = TEE_HANDLE_NULL;
    }

    if (ctx->shared_key) {
        TEE_FreeTransientObject(ctx->shared_key);
        ctx->shared_key = TEE_HANDLE_NULL;
    }

    if (ctx->aes_key) {
        TEE_FreeTransientObject(ctx->aes_key);
        ctx->aes_key = TEE_HANDLE_NULL;
    }

    TEE_Free(ctx);
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_type, TEE_Param params[4]) {
    switch (cmd) {
        case DH_BASIC_GEN_DH_KEYPAIR:
            return generate_keypair(sess_ctx, param_type, params);

        case DH_BASIC_DERIVE_KEY:
            return generate_shared_key(sess_ctx, param_type, params);

        case DH_BASIC_DECRYPT:
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
 
 * scp dh_basic/ta/a49c2ff4-d6c8-4552-b30e-ba847fb6d686.ta wenshuyu@192.168.1.6:/lib/optee_armtz
 * scp dh_basic/host/dh_basic wenshuyu@192.168.1.6:/usr/bin
 */

