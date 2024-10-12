#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "include/hash.h"

static TEE_Result digest(void **sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    (void)sess_ctx;
    TEE_Result res;
    TEE_OperationHandle operation;
    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                                TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if(param_type != exp_param_type) {
        EMSG("param type is not correct\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    res = TEE_IsAlgorithmSupported(USE_DIGEST_ALGORITHM, TEE_CRYPTO_ELEMENT_NONE);
    if(res != TEE_SUCCESS) {
        EMSG("the algorithm is not supported\n");
        return res;
    }

    uint32_t out_size = params[1].memref.size;
    if(out_size < (DIGEST_BITS / 8)) {
        EMSG("digest buffer is too small\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    res = TEE_AllocateOperation(&operation, USE_DIGEST_ALGORITHM, TEE_MODE_DIGEST, 0);
    if(res != TEE_SUCCESS) {
        EMSG("alloc operations failed\n");
        return res;
    }

    res = TEE_DigestDoFinal(operation, params[0].memref.buffer, params[0].memref.size,
                            params[1].memref.buffer, &out_size);
    if(res != TEE_SUCCESS) {
        EMSG("digest failed\n");
        return res;
    }

    params[1].memref.size = out_size;

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
    (void)sess_ctx;
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    (void)sess_ctx;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_type, TEE_Param params[4])
{
    switch(cmd) {
        case HASH_DIGEST:
            return digest(sess_ctx, param_type, params);

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
 
 * scp hash/ta/a4660423-4973-4f91-9bb6-882e7256e3ec.ta wenshuyu@192.168.1.6:/lib/optee_armtz
 * scp hash/host/hash wenshuyu@192.168.1.6:/usr/bin
 */

