#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <tee_client_api.h>

#include "../ta/include/cancel.h"

struct cancel_ctx {
    TEEC_Context ctx;
    TEEC_Session sess;
    pthread_t invoke_thread;
    pthread_t cancel_thread;
    TEEC_Operation op;
};

void *invoke_command_thread(void *arg)
{
    struct cancel_ctx *ctx = (struct cancel_ctx *)arg;
    uint32_t err_origin;
    TEEC_Result res;

	// TA will start delay 5 Second
    res = TEEC_InvokeCommand(&ctx->sess, TA_CANCEL_CMD_DELAY, &ctx->op, &err_origin);
    if (res == TEEC_ERROR_CANCEL)
        printf("operation has been canceled\n");
    else if (res != TEEC_SUCCESS)
        printf("TEEC_InvokeCommand fail res is : 0x%x err_ret 0x%x\n", res, err_origin);
    else
        printf("count complete\n");

    return NULL;
}

void *request_cancellation_thread(void *arg)
{
    struct cancel_ctx *ctx = (struct cancel_ctx *)arg;

    sleep(3); // let TA delay 3 second

    printf("CA request the cancelation...\n");
    TEEC_RequestCancellation(&ctx->op); // TA will stop delay count and return

    return NULL;
}

static void example(struct cancel_ctx *ctx)
{
    memset(&ctx->op, 0, sizeof(ctx->op));

    if (pthread_create(&ctx->invoke_thread, NULL, invoke_command_thread, ctx) != 0) {
        errx(1, "create invoke_command_thread failed");
    }

    if (pthread_create(&ctx->cancel_thread, NULL, request_cancellation_thread, ctx) != 0) {
        errx(1, "create request_cancellation_thread failed");
    }

    pthread_join(ctx->invoke_thread, NULL);
    pthread_join(ctx->cancel_thread, NULL);
}

static void prepare_tee_session(struct cancel_ctx *ctx)
{
    TEEC_UUID uuid = TA_CANCEL_UUID;
    uint32_t origin;
    TEEC_Result res;

    res = TEEC_InitializeContext(NULL, &ctx->ctx);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InitializeContext fail res is : 0x%x err_ret 0x%x\n", res, origin);
        exit(1);
    }

    res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
                   TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_OpenSession fail res is : 0x%x err_ret 0x%x\n", res, origin);
        TEEC_FinalizeContext(&ctx->ctx);
        exit(1);
    }
}

static void terminate_tee_session(struct cancel_ctx *ctx)
{
    TEEC_CloseSession(&ctx->sess);
    TEEC_FinalizeContext(&ctx->ctx);
}

int main()
{
    struct cancel_ctx ctx;

    prepare_tee_session(&ctx);

    example(&ctx);

    terminate_tee_session(&ctx);

    return 0;
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
