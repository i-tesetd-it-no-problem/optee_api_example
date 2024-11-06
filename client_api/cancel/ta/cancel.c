#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "include/cancel.h"

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "include/cancel.h"

#define DELAY_TIME 5

static TEE_Result cmd_delay(void __unused *sess_ctx, uint32_t __unused param_type, TEE_Param __unused params[4])
{
    uint8_t i;
    TEE_Result res;

    TEE_UnmaskCancellation(); // alow to cancel

    IMSG("TA start count...\n\n");
    for (i = DELAY_TIME; i > 0; i--) {

        res = TEE_Wait(1000);
        if (res == TEE_ERROR_CANCEL) {
            IMSG("received cancellation from CA\n\n");
            return res;
        } else if (res != TEE_SUCCESS) {
            
            IMSG("TEE_Wait failed with error: 0x%x\n\n", res);
            return res;
        }

        IMSG("remain %ds\n\n", i - 1);
    }

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

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_type, TEE_Param __unused params[4], void __unused **sess_ctx)
{ 
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *sess_ctx)
{
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_type, TEE_Param params[4])
{
    switch(cmd) {
        case TA_CANCEL_CMD_DELAY:
            return cmd_delay(sess_ctx, param_type, params);
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
 
 * scp cancel/ta/5d39015c-23c2-4a90-b14b-e7721904f3d0.ta wenshuyu@192.168.1.6:/lib/optee_armtz
 * scp cancel/host/cancel wenshuyu@192.168.1.6:/usr/bin
 */

