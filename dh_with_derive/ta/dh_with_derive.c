#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <include/dh_with_derive.h>

// 根据GP规范 TEE_TYPE_GENERIC_SECRET 的类型必须是8的倍数
static int align_to_8(int num) {
    if (num % 8 == 0) 
        return num;
    else 
        return (num + 8 - (num % 8));
}

// DH 会话结构体
struct dh_session {
    TEE_OperationHandle operation;      // 用于密钥派生操作的句柄
    TEE_ObjectHandle local_key_pair;    // 本地密钥对对象句柄
    TEE_ObjectHandle derive_key;        // 派生密钥对象句柄
    enum dh_algorithm_type algo;        // 算法类型
};

// 枚举转 OP-TEE 算法类型函数
static uint32_t get_tee_algorithm(enum dh_algorithm_type type) {
    switch(type) {
        case DH_ALGORITHM_TYPE_ECDH_P192: return TEE_ALG_ECDH_P192;
        case DH_ALGORITHM_TYPE_ECDH_P224: return TEE_ALG_ECDH_P224;
        case DH_ALGORITHM_TYPE_ECDH_P256: return TEE_ALG_ECDH_P256;
        case DH_ALGORITHM_TYPE_ECDH_P384: return TEE_ALG_ECDH_P384;
        case DH_ALGORITHM_TYPE_ECDH_P521: return TEE_ALG_ECDH_P521;
        case DH_ALGORITHM_TYPE_X25519:    return TEE_ALG_X25519;
        default:                          return 0xFFFFFFFF; // 未知算法类型
    }
}

// 验证是否支持指定算法接口需要的参数
// 生成椭圆曲线密钥对时，需要的参数
static uint32_t get_tee_element(enum dh_algorithm_type type) {
    switch (type) {
        case DH_ALGORITHM_TYPE_ECDH_P192:   return TEE_ECC_CURVE_NIST_P192;  // NIST P-192 椭圆曲线
        case DH_ALGORITHM_TYPE_ECDH_P224:   return TEE_ECC_CURVE_NIST_P224;  // NIST P-224 椭圆曲线
        case DH_ALGORITHM_TYPE_ECDH_P256:   return TEE_ECC_CURVE_NIST_P256;  // NIST P-256 椭圆曲线
        case DH_ALGORITHM_TYPE_ECDH_P384:   return TEE_ECC_CURVE_NIST_P384;  // NIST P-384 椭圆曲线
        case DH_ALGORITHM_TYPE_ECDH_P521:   return TEE_ECC_CURVE_NIST_P521;  // NIST P-521 椭圆曲线
        case DH_ALGORITHM_TYPE_X25519:      return TEE_ECC_CURVE_25519;      // 25519 椭圆曲线
        default:                            return 0xFFFFFFFF;              // 未知类型，返回无效值
    }
}

// 根据所选算法类型获取瞬态对象密钥对的类型和大小
static TEE_Result get_keypair_type_and_keysize(enum dh_algorithm_type alg_type, uint32_t *key_type, uint32_t *key_size) {
    if (!key_type || !key_size)
        return TEE_ERROR_BAD_PARAMETERS;

    switch (alg_type) {
        case DH_ALGORITHM_TYPE_ECDH_P192:
            *key_type = TEE_TYPE_ECDH_KEYPAIR;
            *key_size = 192;
            break;
        case DH_ALGORITHM_TYPE_ECDH_P224:
            *key_type = TEE_TYPE_ECDH_KEYPAIR;
            *key_size = 224;
            break;
        case DH_ALGORITHM_TYPE_ECDH_P256:
            *key_type = TEE_TYPE_ECDH_KEYPAIR;
            *key_size = 256;
            break;
        case DH_ALGORITHM_TYPE_ECDH_P384:
            *key_type = TEE_TYPE_ECDH_KEYPAIR;
            *key_size = 384;
            break;
        case DH_ALGORITHM_TYPE_ECDH_P521:
            *key_type = TEE_TYPE_ECDH_KEYPAIR;
            *key_size = 521;
            break;
        case DH_ALGORITHM_TYPE_X25519:
            *key_type = TEE_TYPE_X25519_KEYPAIR;
            *key_size = 32 * 8;
            break;
        default:
            return TEE_ERROR_BAD_PARAMETERS; // 未知算法类型
    }
    return TEE_SUCCESS;
}

// 根据算法类型返回公钥长度
static TEE_Result get_public_key_length(enum dh_algorithm_type algo_type, size_t *key_length) {
    if (!key_length) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    switch (algo_type) {
        case DH_ALGORITHM_TYPE_ECDH_P192:
            *key_length = 1 + 24 + 24;  // 1字节前缀 + 24字节X + 24字节Y
            break;

        case DH_ALGORITHM_TYPE_ECDH_P224:
            *key_length = 1 + 28 + 28;  // 1字节前缀 + 28字节X + 28字节Y
            break;

        case DH_ALGORITHM_TYPE_ECDH_P256:
            *key_length = 1 + 32 + 32;  // 1字节前缀 + 32字节X + 32字节Y
            break;

        case DH_ALGORITHM_TYPE_ECDH_P384:
            *key_length = 1 + 48 + 48;  // 1字节前缀 + 48字节X + 48字节Y
            break;

        case DH_ALGORITHM_TYPE_ECDH_P521:
            *key_length = 1 + 66 + 66;  // 1字节前缀 + 66字节X + 66字节Y
            break;

        case DH_ALGORITHM_TYPE_X25519: // X25519 只有一个X
            *key_length = 32;
            break;

        default:
            return TEE_ERROR_NOT_SUPPORTED; // 未知的算法类型
    }

    return TEE_SUCCESS; // 成功返回
}

// 获取密钥属性类型
static TEE_Result get_key_attribute(enum dh_algorithm_type alg_type, 
                                    uint32_t *public_key_attr_x, uint32_t *public_key_attr_y) {
    if (!public_key_attr_x)
        return TEE_ERROR_BAD_PARAMETERS;

    switch (alg_type) {
        case DH_ALGORITHM_TYPE_ECDH_P192:
        case DH_ALGORITHM_TYPE_ECDH_P224:
        case DH_ALGORITHM_TYPE_ECDH_P256:
        case DH_ALGORITHM_TYPE_ECDH_P384:
        case DH_ALGORITHM_TYPE_ECDH_P521:
            if (!public_key_attr_y)
                return TEE_ERROR_BAD_PARAMETERS;
            *public_key_attr_x = TEE_ATTR_ECC_PUBLIC_VALUE_X; // 椭圆曲线的公钥 X 坐标
            *public_key_attr_y = TEE_ATTR_ECC_PUBLIC_VALUE_Y; // 椭圆曲线的公钥 Y 坐标
            break;
        case DH_ALGORITHM_TYPE_X25519:
            *public_key_attr_x = TEE_ATTR_X25519_PUBLIC_VALUE; // X25519 的公钥属性（只需 X 坐标）
            // 对于 X25519，不需要 Y 坐标，因此不设置 public_key_attr_y
            if (public_key_attr_y)
                *public_key_attr_y = TEE_HANDLE_NULL;
            break;

        default:
            return TEE_ERROR_BAD_PARAMETERS;  // 未知算法类型
    }

    return TEE_SUCCESS;
}

// 释放句柄
static void free_handle(struct dh_session *ctx) {
    if (ctx) {
        if (ctx->operation != TEE_HANDLE_NULL) {
            TEE_FreeOperation(ctx->operation);
            ctx->operation = TEE_HANDLE_NULL;
        }

        if (ctx->derive_key != TEE_HANDLE_NULL) {
            TEE_FreeTransientObject(ctx->derive_key);
            ctx->derive_key = TEE_HANDLE_NULL;
        }

        if(ctx->local_key_pair != TEE_HANDLE_NULL) {
            TEE_FreeTransientObject(ctx->local_key_pair);
            ctx->local_key_pair = TEE_HANDLE_NULL;
        }
    }
}

// 本地生成一个算法对应的密钥对用于测试
// 实际使用时，用户可以自己设置对应算法的密钥对，建议使用持久化存储的密钥对
static TEE_Result generate_key_for_ta(struct dh_session *ctx) {
    TEE_Result ret;
    uint32_t key_type, key_size; // 密钥对类型和大小

    // 获取密钥对类型和密钥大小
    ret = get_keypair_type_and_keysize(ctx->algo, &key_type, &key_size);
    if (ret != TEE_SUCCESS) {
        EMSG("get_keypair_type_and_keysize failed: 0x%x\n", ret);
        return ret;
    }

    // 申请瞬态对象（密钥对)
    ret = TEE_AllocateTransientObject(key_type, key_size, &ctx->local_key_pair);
    if (ret != TEE_SUCCESS) {
        EMSG("TEE_AllocateTransientObject failed: 0x%x\n", ret);
        return ret;
    }

    // 分配操作句柄
    ret = TEE_AllocateOperation(&ctx->operation, get_tee_algorithm(ctx->algo), TEE_MODE_DERIVE, key_size);
    if (ret != TEE_SUCCESS) {
        EMSG("TEE_AllocateOperation failed: 0x%x\n", ret);
        TEE_FreeTransientObject(ctx->local_key_pair);
        return ret;
    }

    // 获取椭圆曲线类型
    uint32_t curve = get_tee_element(ctx->algo);
    if (ctx->algo != DH_ALGORITHM_TYPE_X25519 && curve == 0xFFFFFFFF) {
        EMSG("Unsupported curve for algorithm type: %d\n", ctx->algo);
        TEE_FreeOperation(ctx->operation);
        TEE_FreeTransientObject(ctx->local_key_pair);
        return TEE_ERROR_NOT_SUPPORTED;
    }

    // 初始化密钥对属性 根据GP规范, TEE_TYPE_ECDH_KEYPAIR必须传入一个TEE_ATTR_ECC_CURVE的属性
    // 但是TEE_TYPE_X25519_KEYPAIR不需要传入该属性
    // 保存到上下文的local_key_pair
    TEE_Attribute attrs[1];
    if (ctx->algo != DH_ALGORITHM_TYPE_X25519) {
        TEE_InitValueAttribute(&attrs[0], TEE_ATTR_ECC_CURVE, curve, 0);
        ret = TEE_GenerateKey(ctx->local_key_pair, key_size, attrs, 1);
    } else {
        ret = TEE_GenerateKey(ctx->local_key_pair, key_size, NULL, 0);
    }
    
    if (ret != TEE_SUCCESS) {
        EMSG("TEE_GenerateKey failed: 0x%x\n", ret);
        TEE_FreeOperation(ctx->operation);
        TEE_FreeTransientObject(ctx->local_key_pair);
        return ret;
    }

    // 设置操作句柄的密钥对象
    ret = TEE_SetOperationKey(ctx->operation, ctx->local_key_pair);
    if (ret != TEE_SUCCESS) {
        EMSG("TEE_SetOperationKey failed: 0x%x\n", ret);
        TEE_FreeOperation(ctx->operation);
        TEE_FreeTransientObject(ctx->local_key_pair);
        return ret;
    }

    return TEE_SUCCESS;
}


// 初始化密钥交换环境
static TEE_Result dh_with_derive_init(void *sess_ctx, uint32_t param_types, TEE_Param params[4]) {
    struct dh_session *ctx = (struct dh_session *)sess_ctx;

    TEE_Result ret;

    // 验证参数类型
    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                             TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_type) {
        EMSG("dh_with_derive_init: param_types mismatch");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    free_handle(ctx); // 释放之前的资源

    ctx->algo = params[0].value.a; // 保存当前的算法类型

    // 验证算法是否支持
    ret = TEE_IsAlgorithmSupported(get_tee_algorithm(ctx->algo), get_tee_element(ctx->algo));
    if (ret != TEE_SUCCESS) {
        EMSG("TEE_IsAlgorithmSupported failed: 0x%x\n", ret);
        return ret;
    }

    // 获取不同算法规定的公钥长度
    size_t peer_public_key_size;
    ret = get_public_key_length(ctx->algo, &peer_public_key_size);
    if (ret != TEE_SUCCESS) {
        EMSG("get_public_key_length failed: 0x%x\n", ret);
        return ret;
    }

    // 验证CA传入的公钥长度是否符合标准
    if(ctx->algo != DH_ALGORITHM_TYPE_X25519) {
        // 传统椭圆曲线
        if(params[1].memref.size != peer_public_key_size) {
            EMSG("expected peer public key size %zu, but got %zu\n", peer_public_key_size, params[1].memref.size);
            return TEE_ERROR_BAD_PARAMETERS;
        }
    } else {
        // 基于X25519标准的椭圆曲线固定32字节
        if(params[1].memref.size != 32) {
            EMSG("expected peer public key size %zu, but got %zu\n", (size_t)32, params[1].memref.size);
            return TEE_ERROR_BAD_PARAMETERS;
        }
    }

    // 根据不同算法生成一个本地的密钥对, 用于后续密钥派生
    ret = generate_key_for_ta(ctx);
    if (ret != TEE_SUCCESS) {
        EMSG("generate_key_for_ta failed: 0x%x\n", ret);
        return ret;
    }
    IMSG("TA Alloc Key Pair Successful\n");

    uint32_t public_key_attr_x; // 椭圆曲线的公钥X坐标属性ID
    uint32_t public_key_attr_y; // 椭圆曲线的公钥Y坐标属性ID
    // 根据算法类型获取公钥属性ID
    ret = get_key_attribute(ctx->algo, &public_key_attr_x, 
                            (ctx->algo != DH_ALGORITHM_TYPE_X25519) ? &public_key_attr_y : NULL);
    if (ret != TEE_SUCCESS) {
        EMSG("get_key_attribute failed: 0x%x\n", ret);
        return ret;
    }

    TEE_Attribute attr_pub_key[2]; // 初始化两个属性
    uint8_t *peer_pub_key = params[1].memref.buffer; // CA传入的公钥 : (0x04 + X + Y) 根据标准，04为前缀，表示未压缩
    size_t per_pub_key_size; // 单个公钥长度即 X 或 Y 的长度，两者相等
    if(ctx->algo != DH_ALGORITHM_TYPE_X25519) {
        // 对于非X25519算法，公钥格式为 0x04 + X + Y
        if (peer_pub_key[0] != 0x04) { // 检查前缀
            EMSG("Invalid public key prefix: expected 0x04, got 0x%02x\n", peer_pub_key[0]);
            return TEE_ERROR_BAD_PARAMETERS;
        }
        per_pub_key_size = (peer_public_key_size - 1) / 2; // 排除前缀后的X或Y长度

        // 初始化两个公钥属性
        TEE_InitRefAttribute(&attr_pub_key[0], public_key_attr_x, peer_pub_key + 1, per_pub_key_size);
        TEE_InitRefAttribute(&attr_pub_key[1], public_key_attr_y, peer_pub_key + 1 + per_pub_key_size, per_pub_key_size);
    } else {
        // 对于X25519算法，公钥仅为X
        per_pub_key_size = peer_public_key_size;
        TEE_InitRefAttribute(&attr_pub_key[0], public_key_attr_x, peer_pub_key, per_pub_key_size);
    }
    
    size_t derive_key_need_size;  // 派生密钥所需长度
    ret = get_public_key_length(ctx->algo, &derive_key_need_size);
    if(ret != TEE_SUCCESS) {
        EMSG("get_public_key_length failed: 0x%x\n", ret);
        return ret;
    }

    if(ctx->algo != DH_ALGORITHM_TYPE_X25519)
        derive_key_need_size = (derive_key_need_size - 1) / 2; // 计算派生密钥长度，排除前缀

    // 申请瞬态对象用于派生密钥
    // 根据GP规范 派生密钥类型为 TEE_TYPE_GENERIC_SECRET
    ret = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET, align_to_8(derive_key_need_size), &ctx->derive_key);
    if(ret != TEE_SUCCESS) {
        EMSG("TEE_AllocateTransientObject failed: 0x%x, alloc size is %u", ret, derive_key_need_size);
        return ret;
    }

    // 派生密钥
    // 传统椭圆曲线算法需要传入两个属性，X和Y坐标，X25519算法只需要传入X坐标
    uint32_t attr_count = (ctx->algo != DH_ALGORITHM_TYPE_X25519) ? 2 : 1;
    TEE_DeriveKey(ctx->operation, attr_pub_key, attr_count, ctx->derive_key);
    
    IMSG("TEE_DeriveKey Successful\n");

    return TEE_SUCCESS;
}

// 获取 TA 的公钥
static TEE_Result get_ta_pub_key(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    struct dh_session *ctx = (struct dh_session *)sess_ctx;
    TEE_Result ret;

    // 验证参数类型
    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
                                             TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_type) {
        EMSG("get_ta_pub_key: param_types mismatch");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 根据算法类型获取公钥长度
    size_t pub_key_length;
    ret = get_public_key_length(ctx->algo, &pub_key_length);
    if(ret != TEE_SUCCESS) {
        EMSG("get_public_key_length failed: 0x%x\n", ret);
        return ret;
    }

    // 判断缓冲区是否足够
    if(params[0].memref.size < pub_key_length) {
        EMSG("Output buffer size %zu is too small, required %zu\n", params[0].memref.size, pub_key_length);
        return TEE_ERROR_SHORT_BUFFER;
    }

    uint8_t *output = params[0].memref.buffer; // 返回的buffer地址
    size_t written = 0;

    if(ctx->algo != DH_ALGORITHM_TYPE_X25519) {
        // 对于非X25519算法，未压缩的公钥格式为 0x04 || X || Y
        output[0] = 0x04; // 设置前缀
        written = 1;

        // 获取 X 坐标 提取local_key_pair的TEE_ATTR_ECC_PUBLIC_VALUE_X属性
        size_t x_size;
        ret = TEE_GetObjectBufferAttribute(ctx->local_key_pair, TEE_ATTR_ECC_PUBLIC_VALUE_X, output + written, &x_size);
        if(ret != TEE_SUCCESS) {
            EMSG("TEE_GetObjectBufferAttribute (X) failed: 0x%x\n", ret);
            return ret;
        }
        written += x_size;

        // 获取 Y 坐标 提取local_key_pair的TEE_ATTR_ECC_PUBLIC_VALUE_Y属性
        size_t y_size;
        ret = TEE_GetObjectBufferAttribute(ctx->local_key_pair, TEE_ATTR_ECC_PUBLIC_VALUE_Y, output + written, &y_size);
        if(ret != TEE_SUCCESS) {
            EMSG("TEE_GetObjectBufferAttribute (Y) failed: 0x%x\n", ret);
            return ret;
        }
        written += y_size;
    } else {
        // 对于X25519算法，公钥仅为X
        size_t x_size;
        ret = TEE_GetObjectBufferAttribute(ctx->local_key_pair, TEE_ATTR_X25519_PUBLIC_VALUE, output, &x_size);
        if(ret != TEE_SUCCESS) {
            EMSG("TEE_GetObjectBufferAttribute (X25519) failed: 0x%x\n", ret);
            return ret;
        }
        written = x_size;
    }

    params[0].memref.size = written; // 设置实际写入的大小

    return TEE_SUCCESS;
}

// 获取派生密钥
static TEE_Result get_derive_key(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    struct dh_session *ctx = (struct dh_session *)sess_ctx;
    TEE_Result ret;

    // 验证参数类型
    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
                                             TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_type) {
        EMSG("get_derive_key: param_types mismatch");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 获取派生密钥长度
    size_t local_derive_key_size;
    ret = get_public_key_length(ctx->algo, &local_derive_key_size);
    if(ret != TEE_SUCCESS) {
        EMSG("get_public_key_length failed: 0x%x\n", ret);
        return ret;
    }

    // 对于非X25519，调整派生密钥大小
    if(ctx->algo != DH_ALGORITHM_TYPE_X25519)
        local_derive_key_size = (local_derive_key_size - 1) / 2; // 派生密钥格式为 0x04 || X || Y

    // 检查输入缓冲区大小
    if(params[0].memref.size < local_derive_key_size) {
        EMSG("Input buffer size %zu is too small, required %zu\n", params[0].memref.size, local_derive_key_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 申请内存保存派生密钥
    uint8_t *local_derive_key = TEE_Malloc(local_derive_key_size, TEE_MALLOC_FILL_ZERO);
    if(!local_derive_key) {
        EMSG("TEE_Malloc failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    // 根据GP规范，派生的密钥存储在TEE_ATTR_SECRET_VALUE属性中
    ret = TEE_GetObjectBufferAttribute(ctx->derive_key, TEE_ATTR_SECRET_VALUE, local_derive_key, &local_derive_key_size);
    if(ret != TEE_SUCCESS) {
        EMSG("TEE_GetObjectBufferAttribute failed: 0x%x\n", ret);
        TEE_Free(local_derive_key);
        return ret;
    }

    // 返回给CA
    TEE_MemMove(params[0].memref.buffer, local_derive_key, local_derive_key_size);
    params[0].memref.size = local_derive_key_size;

    // 释放内存
    TEE_Free(local_derive_key);
    return TEE_SUCCESS;
}


/*******************************************************************************
 * Mandatory TA functions.
 ******************************************************************************/

TEE_Result TA_CreateEntryPoint(void) {
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_type, TEE_Param params[4], void **sess_ctx) {
    (void)param_type;
    (void)params;

    struct dh_session *ctx = TEE_Malloc(sizeof(struct dh_session), TEE_MALLOC_FILL_ZERO);
    if (!ctx) {
        EMSG("TEE_Malloc failed, Out of memory");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    *sess_ctx = ctx;
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx) {
    struct dh_session *ctx = (struct dh_session *)sess_ctx;
    free_handle(ctx);
    TEE_Free(ctx);
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_types, TEE_Param params[4]) {
    switch (cmd) {
        case DH_WITH_DERIVE_CMD_INIT:
            return dh_with_derive_init(sess_ctx, param_types, params); /* 生成密钥对并派生密钥 */

        case DH_WITH_DERIVE_CMD_GET_TA_PUBLIC_KEY:
            return get_ta_pub_key(sess_ctx, param_types, params); /* 获取 TA 的公钥 */

        case DH_WITH_DERIVE_CMD_GET_DERIVE_KEY:
            return get_derive_key(sess_ctx, param_types, params); /* 获取派生密钥 */

        default:
            return TEE_ERROR_BAD_PARAMETERS; /* 未知命令 */
    }
}

