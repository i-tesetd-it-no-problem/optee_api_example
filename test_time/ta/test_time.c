#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <time.h>

#include "include/test_time.h"

struct time_ctx{
    
};

static TEE_Result get_sys_time(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    (void)sess_ctx;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Time sys_time;
    TEE_GetSystemTime(&sys_time);

    params[0].value.a = sys_time.seconds;
    params[0].value.b = sys_time.millis;

    return TEE_SUCCESS;
}

static TEE_Result wait(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    (void)sess_ctx;
    TEE_Result res;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    IMSG("start count\n\n");

    uint32_t wait_time = params[0].value.a;

    for(uint32_t i = wait_time; i > 0; i--) {
        res = TEE_Wait(1000);
        if(res != TEE_SUCCESS) {
            EMSG("TEE_Wait failed, res = 0x%x\n", res);
            return res;
        }
        IMSG("remaind secondes: %u\n", i - 1);
    }

    IMSG("\nstop count\n\n");
    return TEE_SUCCESS;
}

static TEE_Result set_persistant_time(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    (void)sess_ctx;
    TEE_Result res;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Time persistant_time;
    persistant_time.seconds = params[0].value.a;
    persistant_time.millis = params[0].value.b;
    res = TEE_SetTAPersistentTime(&persistant_time);
    if(res != TEE_SUCCESS) {
        EMSG("TEE_SetTAPersistentTime failed, res = 0x%x\n", res);
        return res;
    }

    IMSG("TEE_SetTAPersistentTime success\n");

    return TEE_SUCCESS;
}

static TEE_Result get_persistant_time(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    (void)sess_ctx;
    TEE_Result res;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Time persistant_time;
    res = TEE_GetTAPersistentTime(&persistant_time);
    if(res != TEE_SUCCESS) {
        EMSG("TEE_GetTAPersistentTime failed, res = 0x%x\n", res);
        return res;
    }

    params[0].value.a = persistant_time.seconds;
    params[0].value.b = persistant_time.millis;

    return TEE_SUCCESS;
}

static TEE_Result get_ree_time(void *sess_ctx, uint32_t param_type, TEE_Param params[4])
{
    (void)sess_ctx;
    (void)params;

    uint32_t exp_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_type != exp_param_type) {
        EMSG("param type error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Time ree_time;
    TEE_GetREETime(&ree_time);

    IMSG("Second : %u\n", ree_time.seconds);
    IMSG("Millis : %u\n", ree_time.millis);

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
    
    struct time_ctx *ctx = TEE_Malloc(sizeof(struct time_ctx), TEE_MALLOC_FILL_ZERO);
    if(!ctx) {
        EMSG("TEE_Malloc failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    *sess_ctx = ctx;

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    struct time_ctx *ctx = sess_ctx;
    TEE_Free(ctx);
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_type, TEE_Param params[4])
{
    (void)sess_ctx;

    switch(cmd) {
        case TIME_CMD_GET_SYSTIME:
            return get_sys_time(sess_ctx, param_type, params);

        case TIME_CMD_TIME_WAIT:
            return wait(sess_ctx, param_type, params);

        case TIME_CMD_SET_PERSISTANT_TIME:
            return set_persistant_time(sess_ctx, param_type, params);

        case TIME_CMD_GET_PERSISTANT_TIME:
            return get_persistant_time(sess_ctx, param_type, params);

        case TIME_CMD_GET_REE_TIME:
            return get_ree_time(sess_ctx, param_type, params);

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
 
 * scp test_time/ta/13010e37-4220-4a0f-bb68-882f91d9349b.ta wenshuyu@192.168.1.6:/lib/optee_armtz
 * scp test_time/host/test_time wenshuyu@192.168.1.6:/usr/bin
 */

