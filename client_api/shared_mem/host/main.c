#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tee_client_api.h>

#include "../ta/include/shared_mem.h"

#define BUFFER_SIZE 256

char* msg = "Hello TA\n";
uint8_t reg_buf[BUFFER_SIZE];

struct shared_mem_ctx {
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_SharedMemory shm_alloc;
	TEEC_SharedMemory shm_register;
};

static void alloc_example(struct shared_mem_ctx *ctx)
{
    TEEC_Result res;
    uint32_t err_origin;
    TEEC_Operation op;

	// send
    memset(&op, 0, sizeof(op));
    memcpy(ctx->shm_alloc.buffer, msg, strlen(msg));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].memref.parent = &ctx->shm_alloc;
    op.params[0].memref.offset = 0;
    op.params[0].memref.size = strlen(msg);

    res = TEEC_InvokeCommand(&ctx->sess, SHARED_MEM_CA_TO_TA, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        errx(1, "send msg failed with code 0x%x", res);
    }

	// recieve
    memset(&op, 0, sizeof(op));
    memset(ctx->shm_alloc.buffer, 0, BUFFER_SIZE);
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].memref.parent = &ctx->shm_alloc;
    op.params[0].memref.offset = 0;
    op.params[0].memref.size = BUFFER_SIZE;

    res = TEEC_InvokeCommand(&ctx->sess, SHARED_MEM_TA_TO_CA, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        errx(1, "recv msg failed with code 0x%x", res);
    }

	uint8_t *msg = op.params[0].memref.parent->buffer;
	for(uint32_t i = 0; i < op.params[0].memref.size; i++)
        printf("%c", msg[i]);
    printf("\n\n");
}

static void register_example(struct shared_mem_ctx *ctx)
{
    TEEC_Result res;
    uint32_t err_origin;
    TEEC_Operation op;

	// send
    memset(&op, 0, sizeof(op));
    memcpy(ctx->shm_register.buffer, msg, strlen(msg));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].memref.parent = &ctx->shm_register;
    op.params[0].memref.offset = 0;
    op.params[0].memref.size = strlen(msg);

    res = TEEC_InvokeCommand(&ctx->sess, SHARED_MEM_CA_TO_TA, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        errx(1, "send msg failed with code 0x%x", res);
    }

	// recieve
    memset(&op, 0, sizeof(op));
    memset(ctx->shm_register.buffer, 0, BUFFER_SIZE);
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].memref.parent = &ctx->shm_register;
    op.params[0].memref.offset = 0;
    op.params[0].memref.size = BUFFER_SIZE;

    res = TEEC_InvokeCommand(&ctx->sess, SHARED_MEM_TA_TO_CA, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        errx(1, "recv msg failed with code 0x%x", res);
    }

	uint8_t *msg = op.params[0].memref.parent->buffer;
	for(uint32_t i = 0; i < op.params[0].memref.size; i++)
        printf("%c", msg[i]);
    printf("\n\n");
}

static void example(struct shared_mem_ctx *ctx)
{
	alloc_example(ctx);
	register_example(ctx);
}

static void prepare_tee_session(struct shared_mem_ctx *ctx)
{
    TEEC_UUID uuid = TA_SHARED_MEM_UUID;
    uint32_t origin;
    TEEC_Result res;

    res = TEEC_InitializeContext(NULL, &ctx->ctx);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InitializeContext failed with code 0x%x", res);
        exit(0);
    }

	// alloc shrd mem
    ctx->shm_alloc.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
    ctx->shm_alloc.size = BUFFER_SIZE;
    res = TEEC_AllocateSharedMemory(&ctx->ctx, &ctx->shm_alloc);
    if(res != TEEC_SUCCESS) {
        errx(1, "TEEC_AllocateSharedMemory failed with code 0x%x", res);
    }

	// register shrd mem
	ctx->shm_register.buffer = reg_buf;
	ctx->shm_register.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	ctx->shm_register.size = BUFFER_SIZE;
	res = TEEC_RegisterSharedMemory(&ctx->ctx, &ctx->shm_register);
	if(res != TEEC_SUCCESS) {
        errx(1, "TEEC_RegisterSharedMemory failed with code 0x%x", res);
    }

    res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
                   TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_OpenSession failed with code 0x%x origin 0x%x", res, origin);
        exit(0);
    }
}

static void terminate_tee_session(struct shared_mem_ctx *ctx)
{
    TEEC_CloseSession(&ctx->sess);

	// free shrd mem
    TEEC_ReleaseSharedMemory(&ctx->shm_alloc);

	// free register mem
    TEEC_ReleaseSharedMemory(&ctx->shm_register);

    TEEC_FinalizeContext(&ctx->ctx);
}

int main()
{
    struct shared_mem_ctx ctx;

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

 * scp shared_mem/ta/79457d8a-e919-46f4-8ad1-bb7243388cc5.ta wenshuyu@192.168.1.6:/lib/optee_armtz
 * scp shared_mem/host/shared_mem wenshuyu@192.168.1.6:/usr/bin
 */

