#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "include/rng.h"

static TEE_Result generate_random(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    (void)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, 
                                             TEE_PARAM_TYPE_NONE,
                                             TEE_PARAM_TYPE_NONE,
                                             TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error for obj_exists\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t random_size = params[0].memref.size;
    uint8_t *random = TEE_Malloc(random_size, TEE_MALLOC_FILL_ZERO);
    if(!random) {
        EMSG("Alloc Memory Failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    TEE_GenerateRandom(random, random_size);
    TEE_MemMove(params[0].memref.buffer, random, random_size);

    TEE_Free(random);

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
        case GENERATE_RANDOM:
            return generate_random(sess_ctx, param_type, params);

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
 
 * scp rng/ta/5adc202b-4e1b-4590-8193-45f8ff44236e.ta wenshuyu@192.168.1.6:/lib/optee_armtz
 * scp rng/host/rng wenshuyu@192.168.1.6:/usr/bin
 */

