#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "include/ecdh_xxx.h"

// 根据GP规范 TEE_TYPE_GENERIC_SECRET 的类型必须是8的倍数
static int align_to_8(int num) {
    if (num % 8 == 0) 
        return num;
    else 
        return (num + 8 - (num % 8));
}

struct ecdh_ctx {
    TEE_OperationHandle operation;
    TEE_ObjectHandle keypair;
    TEE_ObjectHandle shared_key;
    TEE_ObjectHandle aes_key; 
};

static TEE_Result generate_keypair(struct ecdh_ctx* sess_ctx, uint32_t param_type, TEE_Param params[4]) {
    TEE_Result res;
    TEE_Attribute attrs;
    struct ecdh_ctx *ctx = (struct ecdh_ctx *)sess_ctx;
    uint32_t exp_param_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_OUTPUT, 
        TEE_PARAM_TYPE_NONE,  
        TEE_PARAM_TYPE_NONE,  
        TEE_PARAM_TYPE_NONE);

    if (param_type != exp_param_type) {
        EMSG("Parameter types mismatch\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint8_t *public_key = params[0].memref.buffer;
    uint32_t out_size = params[0].memref.size;
    uint32_t pub_key_len = 0;

    if (ctx->keypair != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(ctx->keypair);
        ctx->keypair = TEE_HANDLE_NULL;
    }

    res = TEE_AllocateTransientObject(TEE_TYPE_ECDH_KEYPAIR, KEYPAIR_BITS, &ctx->keypair);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to allocate transient object, res = 0x%x\n", res);
        return res;
    }
    
    TEE_InitValueAttribute(&attrs, TEE_ATTR_ECC_CURVE, USE_ELEMENT, 0);
    res = TEE_GenerateKey(ctx->keypair, KEYPAIR_BITS, &attrs, 1);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to generate keypair, res = 0x%x\n", res);
        goto err_free_keypair;
    }

    if (pub_key_len + 1 > out_size) {
        EMSG("Public key buffer is too small for identifier\n");
        res = TEE_ERROR_SHORT_BUFFER;
        goto err_free_keypair;
    }
    public_key[pub_key_len++] = 0x04; 

    uint32_t x_size = 0;
    res = TEE_GetObjectBufferAttribute(ctx->keypair, TEE_ATTR_ECC_PUBLIC_VALUE_X, NULL, &x_size);
    if (res != TEE_ERROR_SHORT_BUFFER) {
        EMSG("Failed to get required size for X value, res = 0x%x\n", res);
        goto err_free_keypair;
    }

    if ((pub_key_len + x_size) > out_size) {
        EMSG("Public key buffer is too small for X value\n");
        res = TEE_ERROR_SHORT_BUFFER;
        goto err_free_keypair;
    }

    res = TEE_GetObjectBufferAttribute(ctx->keypair, TEE_ATTR_ECC_PUBLIC_VALUE_X,
                                       public_key + pub_key_len, &x_size);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to get X value, res = 0x%x\n", res);
        goto err_free_keypair;
    }
    pub_key_len += x_size;

    uint32_t y_size = 0;
    res = TEE_GetObjectBufferAttribute(ctx->keypair, TEE_ATTR_ECC_PUBLIC_VALUE_Y, NULL, &y_size);
    if (res != TEE_ERROR_SHORT_BUFFER) {
        EMSG("Failed to get required size for Y value, res = 0x%x\n", res);
        goto err_free_keypair;
    }

    if ((pub_key_len + y_size) > out_size) {
        EMSG("Public key buffer is too small for Y value\n");
        res = TEE_ERROR_SHORT_BUFFER;
        goto err_free_keypair;
    }

    res = TEE_GetObjectBufferAttribute(ctx->keypair, TEE_ATTR_ECC_PUBLIC_VALUE_Y,
                                       public_key + pub_key_len, &y_size);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to get Y value, res = 0x%x\n", res);
        goto err_free_keypair;
    }
    pub_key_len += y_size;

    params[0].memref.size = pub_key_len;

    IMSG("\nKey pair generated successfully, size is %u\n\n", pub_key_len);

    return TEE_SUCCESS;

err_free_keypair:
    if (ctx->keypair) {
        TEE_FreeTransientObject(ctx->keypair);
        ctx->keypair = TEE_HANDLE_NULL;
    }

    return res;
}


static TEE_Result generate_shared_key(struct ecdh_ctx* sess_ctx, uint32_t param_type, TEE_Param params[4]) {
    TEE_Result res;
    TEE_Attribute attr[2];
    struct ecdh_ctx *ctx = (struct ecdh_ctx *)sess_ctx;
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

    res = TEE_AllocateOperation(&ctx->operation, USE_ECDSA_ALGORITHM, TEE_MODE_DERIVE, KEYPAIR_BITS);
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

    TEE_InitRefAttribute(&attr[0], TEE_ATTR_ECC_PUBLIC_VALUE_X, params[0].memref.buffer, params[0].memref.size);
    TEE_InitRefAttribute(&attr[1], TEE_ATTR_ECC_PUBLIC_VALUE_Y, params[1].memref.buffer, params[1].memref.size);

    TEE_DeriveKey(ctx->operation, attr, 2, ctx->shared_key);
    
    uint8_t shared_secret[KEYPAIR_SIZE];
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

    TEE_Attribute attr_shrd;
    TEE_InitRefAttribute(&attr_shrd, TEE_ATTR_SECRET_VALUE, aes_key, aes_key_len);
    res = TEE_PopulateTransientObject(ctx->aes_key, &attr_shrd, 1);
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

static TEE_Result decrypt(struct ecdh_ctx* sess_ctx, uint32_t param_type, TEE_Param params[4]) {
    TEE_Result res;
    struct ecdh_ctx *ctx = (struct ecdh_ctx *)sess_ctx;
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

    res = TEE_AllocateOperation(&ctx->operation, TEE_ALG_AES_CTR, TEE_MODE_DECRYPT, AES_SECRET_BITS);
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

    struct ecdh_ctx* ctx = TEE_Malloc(sizeof(struct ecdh_ctx), TEE_MALLOC_FILL_ZERO);
    if (!ctx) {
        EMSG("Memory allocation failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    *sess_ctx = ctx;

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx) {
    struct ecdh_ctx* ctx = (struct ecdh_ctx *)sess_ctx;

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
        case ECDH_GEN_DH_KEYPAIR:
            return generate_keypair(sess_ctx, param_type, params);

        case ECDH_DERIVE_KEY:
            return generate_shared_key(sess_ctx, param_type, params);

        case ECDH_DECRYPT:
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
 
 * scp ecdh_xxx/ta/c7df3d74-69f8-45b0-9fe4-f4944019e722.ta wenshuyu@192.168.1.6:/lib/optee_armtz
 * scp ecdh_xxx/host/ecdh_xxx wenshuyu@192.168.1.6:/usr/bin
 */

