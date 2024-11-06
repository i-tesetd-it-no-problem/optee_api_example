#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>

#include "include/shared_mem.h"

struct shrd_mme_ctx {

};

static TEE_Result from_ca(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    (void)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t in_size = params[0].memref.size;
    uint8_t *msg = params[0].memref.buffer;
    for(uint32_t i = 0; i < in_size; i++)
        printf("%c", msg[i]);
    printf("\n\n");

    return TEE_SUCCESS;
}

static TEE_Result to_ca(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    (void)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    char msg[] = "Hello CA\n";
    uint32_t out_size = params[0].memref.size;
    if(out_size < strlen(msg)) {
        EMSG("CA buffer is too small\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_MemMove(params[0].memref.buffer, msg, strlen(msg));
    params[0].memref.size = strlen(msg);

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

    struct shrd_mme_ctx *ctx = TEE_Malloc(sizeof(struct shrd_mme_ctx), TEE_MALLOC_FILL_ZERO);
    if(!ctx) {
        EMSG("alloc context failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    *sess_ctx = ctx;

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    struct shrd_mme_ctx *ctx = (struct shrd_mme_ctx *)sess_ctx;

    TEE_Free(ctx);
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_type, TEE_Param params[4])
{
    switch(cmd) {
        default:
            case SHARED_MEM_CA_TO_TA:
                return from_ca(sess_ctx, param_type, params);

            case SHARED_MEM_TA_TO_CA:
                return to_ca(sess_ctx, param_type, params);

            return TEE_ERROR_BAD_PARAMETERS;
    }
}

/**
 * @brief 配置到开发板指令

 * 注意: 开发本需提前配置好SSH环境, 
 * 根文件系统也需要支持OPTEE, buildroot自行配置

 * /lib/optee_armtz 是OPTEE寻找TA的默认地址
 * /usr/bin 让CA目标文件可以直接当作命令运行
 
 * scp shared_mem/ta/79457d8a-e919-46f4-8ad1-bb7243388cc5.ta wenshuyu@192.168.1.6:/lib/optee_armtz
 * scp shared_mem/host/shared_mem wenshuyu@192.168.1.6:/usr/bin
 */

