#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "include/aes_gcm_ccm.h"

struct aes_gcm_ccm_ctx {
    TEE_OperationHandle key_op_handle; /* 操作句柄 */
    TEE_ObjectHandle key_obj_handle;   /* 密钥对象句柄 */
    uint8_t key_data[AES_KEY_BYTES_SIZE]; /* 密钥数据 */
    uint8_t iv_data[AES_IV_BYTES_SIZE];   /* IV数据 */
};

/* 初始化环境 */
static TEE_Result aes_prepare(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result ret;
    TEE_Attribute attr; /* 对象属性 */
    struct aes_gcm_ccm_ctx *ctx = (struct aes_gcm_ccm_ctx *)sess_ctx; /* 会话上下文 */

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_VALUE_INPUT,
                                              TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE);

    if (param_type != exp_param_type) {
        EMSG("aes_prepare failed, param_type is not correct\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* 此案例只支持GCM和CCM两种模式 */
    if (params[0].value.a != AES_ALGORITHM_GCM && params[0].value.a != AES_ALGORITHM_CCM) {
        EMSG("aes_prepare failed, cipher mode is not correct\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* 加密或者解密 */
    if (params[1].value.a != AES_CIPHER_MODE_ENCRYPT && params[1].value.a != AES_CIPHER_MODE_DECRYPT) {
        EMSG("aes_prepare failed, cipher mode is not correct\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* AES-128 */
    if (params[2].memref.size != AES_KEY_BYTES_SIZE) {
        EMSG("aes_prepare failed, input key size is %u, expected size is %u\n", params[2].memref.size, AES_KEY_BYTES_SIZE);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t alg = (params[0].value.a == AES_ALGORITHM_GCM) ? TEE_ALG_AES_GCM : TEE_ALG_AES_CCM;
    uint32_t mode = (params[1].value.a == AES_CIPHER_MODE_ENCRYPT) ? TEE_MODE_ENCRYPT : TEE_MODE_DECRYPT;

     /* 重置操作句柄 */
    if (ctx->key_op_handle != TEE_HANDLE_NULL){
        TEE_FreeOperation(ctx->key_op_handle);
        ctx->key_op_handle = TEE_HANDLE_NULL;
    }
    /* 申请操作句柄 */
    ret = TEE_AllocateOperation(&ctx->key_op_handle, alg, mode, AES_KEY_BITS_SIZE);
    if (ret != TEE_SUCCESS) {
        EMSG("aes_prepare failed, allocate operation failed, ret is 0x%x\n", ret);
        ctx->key_op_handle = TEE_HANDLE_NULL;
        return ret;
    }

     /* 重置密钥对象句柄 */
    if (ctx->key_obj_handle != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(ctx->key_obj_handle);
        ctx->key_obj_handle = TEE_HANDLE_NULL;
    }
    /* 申请临时密钥对象 */
    ret = TEE_AllocateTransientObject(TEE_TYPE_AES, AES_KEY_BITS_SIZE, &ctx->key_obj_handle);
    if (ret != TEE_SUCCESS) {
        EMSG("aes_prepare failed, allocate transient object failed, ret is 0x%x\n", ret);
        goto err;
    }

    /* 复制密钥 */
    TEE_MemMove(ctx->key_data, params[2].memref.buffer, AES_KEY_BYTES_SIZE);

    /* 初始化密钥属性 */
    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, ctx->key_data, AES_KEY_BYTES_SIZE);

    /* 设置密钥属性 */
    ret = TEE_PopulateTransientObject(ctx->key_obj_handle, &attr, 1);
    if (ret != TEE_SUCCESS) {
        EMSG("aes_prepare failed, populate transient object failed, ret is 0x%x\n", ret);
        goto err;
    }

    /* 设置操作句柄的密钥对象 */
    ret = TEE_SetOperationKey(ctx->key_op_handle, ctx->key_obj_handle);
    if (ret != TEE_SUCCESS) {
        EMSG("aes_prepare failed, set operation key failed, ret is 0x%x\n", ret);
        goto err;
    }

    IMSG("aes_prepare successful\n");

    return TEE_SUCCESS;

err:
    if (ctx->key_op_handle)
        TEE_FreeOperation(ctx->key_op_handle);
    ctx->key_op_handle = TEE_HANDLE_NULL;

    if (ctx->key_obj_handle)
        TEE_FreeTransientObject(ctx->key_obj_handle);
    ctx->key_obj_handle = TEE_HANDLE_NULL;

    return ret;
}

/* 初始化参数 */
static TEE_Result aes_init(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result ret;
    struct aes_gcm_ccm_ctx *ctx = (struct aes_gcm_ccm_ctx *)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_VALUE_INPUT,
                                              TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE);

    /* 验证参数类型 */
    if (param_type != exp_param_type) {
        EMSG("aes_init failed, param_type is not correct\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t iv_size = params[0].memref.size;  /* 初始化向量长度 */
    uint32_t tag_len = params[1].value.a;      /* 认证标签长度（字节） */
    uint32_t aad_len = params[1].value.b;      /* 附加数据长度 */
    uint32_t payload_len = params[2].value.a;  /* 有效载荷长度 */

    /* 检查 IV 长度 */
    if (iv_size != AES_IV_BYTES_SIZE) {
        EMSG("aes_init failed, iv size is %u, expected is %u\n", iv_size, AES_IV_BYTES_SIZE);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* 检查认证标签长度 */
    if (tag_len != AES_TAG_BYTES_SIZE) {
        EMSG("aes_init failed, tag length is %u, expected is %u\n", tag_len, AES_TAG_BYTES_SIZE);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* 确认操作句柄有效 */
    if(ctx->key_op_handle == TEE_HANDLE_NULL) {
        EMSG("aes_init failed, bad state\n");
        return TEE_ERROR_BAD_STATE;
    }
    
    /* 复制 IV */
    TEE_MemMove(ctx->iv_data, params[0].memref.buffer, AES_IV_BYTES_SIZE);

    /* 初始化 AE 操作 */
    ret = TEE_AEInit(ctx->key_op_handle, ctx->iv_data, AES_IV_BYTES_SIZE, tag_len * 8, aad_len, payload_len);
    if (ret != TEE_SUCCESS) {
        EMSG("aes_init failed, ret is 0x%x\n", ret);
        return ret;
    }

    IMSG("aes_init successful\n");

    return TEE_SUCCESS;
}

/* 认证加密 */
static TEE_Result aes_encrypt(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result ret;
    struct aes_gcm_ccm_ctx *ctx = (struct aes_gcm_ccm_ctx *)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,  /* 明文输入 */
                                              TEE_PARAM_TYPE_MEMREF_OUTPUT, /* 密文输出 */
                                              TEE_PARAM_TYPE_MEMREF_OUTPUT, /* 认证标签输出 */
                                              TEE_PARAM_TYPE_NONE);

    /* 验证参数 */
    if (param_type != exp_param_type) {
        EMSG("aes_encrypt failed, param_type is not correct\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* 输出缓冲区必须足够大 */
    if (params[1].memref.size < params[0].memref.size) {
        EMSG("aes_encrypt failed, output size is smaller than input size\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* 检查认证标签缓冲区大小 */
    if (params[2].memref.size < AES_TAG_BYTES_SIZE) {
        EMSG("aes_encrypt failed, tag buffer size is too small\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* 确认操作句柄有效 */
    if(ctx->key_op_handle == TEE_HANDLE_NULL) {
        EMSG("aes_init failed, bad state\n");
        return TEE_ERROR_BAD_STATE;
    }

    // AES-GCM模式下 如果数据量很多可以多次调用TEE_AEUpdate，每次处理一部分数据
    // 但只有最后调用TEE_AEEncryptFinal才可以得到认证标签，不然只会加密
    // ret = TEE_AEUpdate(ctx->key_op_handle,
    //                    params[0].memref.buffer, params[0].memref.size, /* 输入明文 */
    //                    params[1].memref.buffer, &params[1].memref.size); /* 输出密文 */
    // if (ret != TEE_SUCCESS) {
    //     EMSG("TEE_AEUpdate failed, ret is 0x%x\n", ret);
    //     return ret;
    // }

    /* 完成加密且获取认证标签 */
    uint32_t tag_len = AES_TAG_BYTES_SIZE;
    ret = TEE_AEEncryptFinal(ctx->key_op_handle,
                             params[0].memref.buffer, params[0].memref.size, /* 明文 */
                             params[1].memref.buffer, &params[1].memref.size, /* 密文 */
                             params[2].memref.buffer, &tag_len); /* 认证标签 */
    if (ret != TEE_SUCCESS) {
        EMSG("TEE_AEEncryptFinal failed, ret is 0x%x\n", ret);
        return ret;
    }

    /* 更新认证标签实际长度 */
    params[2].memref.size = tag_len;

    IMSG("aes_encrypt successful\n");

    return TEE_SUCCESS;
}

/* 认证解密 */
static TEE_Result aes_decrypt(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    TEE_Result ret;
    struct aes_gcm_ccm_ctx *ctx = (struct aes_gcm_ccm_ctx *)sess_ctx;
    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,  /* 密文输入 */
                                              TEE_PARAM_TYPE_MEMREF_OUTPUT, /* 明文输出 */
                                              TEE_PARAM_TYPE_MEMREF_INPUT,  /* 认证标签输入 */
                                              TEE_PARAM_TYPE_NONE);

    /* 验证参数 */
    if (param_type != exp_param_type) {
        EMSG("aes_decrypt failed, param_type is not correct\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* 输出缓冲区必须足够大 */
    if (params[1].memref.size < params[0].memref.size) {
        EMSG("aes_decrypt failed, output size is smaller than input size\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* 检查认证标签大小 */
    if (params[2].memref.size != AES_TAG_BYTES_SIZE) {
        EMSG("aes_decrypt failed, tag length is %u, expected is %u\n", params[2].memref.size, AES_TAG_BYTES_SIZE);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* 确认操作句柄有效 */
    if(ctx->key_op_handle == TEE_HANDLE_NULL) {
        EMSG("aes_init failed, bad state\n");
        return TEE_ERROR_BAD_STATE;
    }

    // AES-GCM模式下如果数据量很多可以多次调用TEE_AEUpdate，每次处理一部分数据
    // 但只有最后调用TEE_AEEncryptFinal才可以得到认证标签，不然只会解密
    // ret = TEE_AEUpdate(ctx->key_op_handle,
    //                    params[0].memref.buffer, params[0].memref.size,  /* 输入密文 */
    //                    params[1].memref.buffer, &params[1].memref.size); /* 输出明文 */
    // if (ret != TEE_SUCCESS) {
    //     EMSG("TEE_AEUpdate failed, ret is 0x%x\n", ret);
    //     return ret;
    // }

    // 此处一定要复制到TEE侧的内存当中, 不然会Panic， TEE_Malloc申请的内存是安全的,tag原区域为共享内存,非安全
    uint8_t tag_len = params[2].memref.size;
    uint8_t *tag = TEE_Malloc(tag_len, TEE_MALLOC_FILL_ZERO);
    if(!tag) {
        EMSG("aes_decrypt failed, TEE_Malloc failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(tag, params[2].memref.buffer, tag_len);

    size_t out_len = params[1].memref.size;

    /* 完成解密操作，验证认证标签 */
    ret = TEE_AEDecryptFinal(ctx->key_op_handle,
                             params[0].memref.buffer, params[0].memref.size,  /* 输入密文 */
                             params[1].memref.buffer, &out_len, /* 输出明文 */
                             tag, tag_len); /* 输入认证标签 */
    if (ret != TEE_SUCCESS) {
        EMSG("TEE_AEDecryptFinal failed, ret is 0x%x\n", ret);
        return ret;
    }

    params[1].memref.size = out_len;

    IMSG("aes_decrypt successful\n");
    TEE_Free(tag);

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

    /* 初始化会话上下文 */
    struct aes_gcm_ccm_ctx *ctx = TEE_Malloc(sizeof(struct aes_gcm_ccm_ctx), TEE_MALLOC_FILL_ZERO);
    if (!ctx)
        return TEE_ERROR_OUT_OF_MEMORY;

    ctx->key_op_handle = TEE_HANDLE_NULL;
    ctx->key_obj_handle = TEE_HANDLE_NULL;

    *sess_ctx = ctx;

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    struct aes_gcm_ccm_ctx *ctx = (struct aes_gcm_ccm_ctx *)sess_ctx;

    /* 释放会话上下文 */
    if (ctx->key_op_handle != TEE_HANDLE_NULL) 
        TEE_FreeOperation(ctx->key_op_handle);
    ctx->key_op_handle = TEE_HANDLE_NULL;

    if (ctx->key_obj_handle != TEE_HANDLE_NULL) 
        TEE_FreeTransientObject(ctx->key_obj_handle);
    ctx->key_obj_handle = TEE_HANDLE_NULL;

    TEE_Free(ctx);
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_type, TEE_Param params[4])
{
    switch (cmd) {
    case TA_AES_GCM_CCM_CMD_PREPARE:
        return aes_prepare(sess_ctx, param_type, params); /* 准备环境 */

    case TA_AES_GCM_CCM_CMD_INIT:
        return aes_init(sess_ctx, param_type, params); /* 初始化参数 */

    case TA_AES_GCM_CCM_CMD_ENCRYPT:
        return aes_encrypt(sess_ctx, param_type, params); /* 认证加密 */

    case TA_AES_GCM_CCM_CMD_DECRYPT:
        return aes_decrypt(sess_ctx, param_type, params); /* 认证解密 */

    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }
}
