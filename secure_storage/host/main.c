#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tee_client_api.h>

#include "../ta/include/secure_storage.h"

#define OBJECT_SIZE		(256)

char *name_1 = "secure_storage_old";
char *name_2 = "secure_storage_new";

char *message = "Hello, secure storage!";

struct secure_storage_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

typedef enum {
	TEE_DATA_SEEK_SET = 0,
	TEE_DATA_SEEK_CUR = 1,
	TEE_DATA_SEEK_END = 2
} TEE_Whence;

static void obj_create(struct secure_storage_ctx *ctx)
{
	TEEC_Result res;
	uint32_t err_origin;
	TEEC_Operation op;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = name_1;
	op.params[0].tmpref.size = strlen(name_1) + 1;
	op.params[1].value.a = OBJECT_SIZE;

	res = TEEC_InvokeCommand(&ctx->sess, SECURE_STORAGE_CMD_CREATE, &op, &err_origin);
	if(res != TEEC_SUCCESS) {
		errx(1, "Object created failed with code 0x%x origin 0x%x", res, err_origin);
	}
}

static void obj_open(struct secure_storage_ctx *ctx)
{
	TEEC_Result res;
	uint32_t err_origin;
	TEEC_Operation op;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = name_1;
	op.params[0].tmpref.size = strlen(name_1) + 1;

	res = TEEC_InvokeCommand(&ctx->sess, SECURE_STORAGE_CMD_OPEN, &op, &err_origin);
	if(res != TEEC_SUCCESS) {
		errx(1, "Object obj_open failed with code 0x%x origin 0x%x", res, err_origin);
	}
}

static void obj_rename(struct secure_storage_ctx *ctx)
{
	TEEC_Result res;
	uint32_t err_origin;
	TEEC_Operation op;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = name_1;
	op.params[0].tmpref.size = strlen(name_1) + 1;
	op.params[1].tmpref.buffer = name_1;
	op.params[1].tmpref.size = strlen(name_1) + 1;

	res = TEEC_InvokeCommand(&ctx->sess, SECURE_STORAGE_CMD_RENAME, &op, &err_origin);
	if(res == TEEC_ERROR_ACCESS_CONFLICT) {
		printf("the destinated object name is already existed\n\n");
		return;
	}else if(res != TEEC_SUCCESS) {
		printf("obj_rename failed with code 0x%x origin 0x%x\n\n", res, err_origin);
		return;
	} 

	printf("obj_rename success\n\n");
}

static void obj_write(struct secure_storage_ctx *ctx)
{
	TEEC_Result res;
	uint32_t err_origin;
	TEEC_Operation op;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = name_1;
	op.params[0].tmpref.size = strlen(name_1) + 1;
	op.params[1].tmpref.buffer = message;
	op.params[1].tmpref.size = strlen(message) + 1;

	res = TEEC_InvokeCommand(&ctx->sess, SECURE_STORAGE_CMD_WRITE, &op, &err_origin);
	if(res != TEEC_SUCCESS) {
		errx(1, "obj_write failed with code 0x%x origin 0x%x", res, err_origin);
	}

	printf("obj_write success\n\n");
}

static void obj_seek(struct secure_storage_ctx *ctx, uint32_t offset, TEE_Whence whence)
{
	TEEC_Result res;
	uint32_t err_origin;
	TEEC_Operation op;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = name_1;
	op.params[0].tmpref.size = strlen(name_1) + 1;
	op.params[1].value.a = offset;
	op.params[1].value.b = whence;

	res = TEEC_InvokeCommand(&ctx->sess, SECURE_STORAGE_CMD_SEEK, &op, &err_origin);
	if(res != TEEC_SUCCESS) {
		errx(1, "obj_seek failed with code 0x%x origin 0x%x", res, err_origin);
	}

	printf("obj_seek success\n\n");
}

static void obj_read(struct secure_storage_ctx *ctx)
{
	TEEC_Result res;
	uint32_t err_origin;
	TEEC_Operation op;
	uint8_t read_buf[OBJECT_SIZE];

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = name_1;
	op.params[0].tmpref.size = strlen(name_1) + 1;
	op.params[1].tmpref.buffer = read_buf;
	op.params[1].tmpref.size = OBJECT_SIZE;

	res = TEEC_InvokeCommand(&ctx->sess, SECURE_STORAGE_CMD_READ, &op, &err_origin);
	if(res != TEEC_SUCCESS) {
		errx(1, "obj_read failed with code 0x%x origin 0x%x", res, err_origin);
	}

	printf("obj_read success\n\n");
	for(int i = 0; i < op.params[1].tmpref.size; i++)	{
		printf("%c", read_buf[i]);
	}
	printf("\n\n");
}

static void obj_close(struct secure_storage_ctx *ctx)
{
	TEEC_Result res;
	uint32_t err_origin;
	TEEC_Operation op;

	memset(&op, 0, sizeof(op));

	res = TEEC_InvokeCommand(&ctx->sess, SECURE_STORAGE_CMD_CLOSE, &op, &err_origin);
	if(res != TEEC_SUCCESS) {
		errx(1, "obj_close failed with code 0x%x origin 0x%x", res, err_origin);
	}

	printf("obj_close success\n\n");
}

static void obj_delete(struct secure_storage_ctx *ctx)
{
	TEEC_Result res;
	uint32_t err_origin;
	TEEC_Operation op;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = name_1;
	op.params[0].tmpref.size = strlen(name_1) + 1;

	res = TEEC_InvokeCommand(&ctx->sess, SECURE_STORAGE_CMD_DELETE, &op, &err_origin);
	if(res != TEEC_SUCCESS) {
		errx(1, "obj_delete failed with code 0x%x origin 0x%x", res, err_origin);
	}

	printf("obj_delete success\n\n");
}

static void example(struct secure_storage_ctx *ctx)
{
	obj_create(ctx);
	// obj_rename(ctx);

	obj_open(ctx);
	obj_write(ctx);
	obj_seek(ctx, 0, TEE_DATA_SEEK_SET);
	obj_read(ctx);

	obj_seek(ctx, 7, TEE_DATA_SEEK_SET);
	obj_read(ctx);
	obj_close(ctx);

	obj_delete(ctx);
}

static void prepare_tee_session(struct secure_storage_ctx *ctx)
{
	TEEC_UUID uuid = TA_SECURE_STORAGE_UUID;
	uint32_t origin;
	TEEC_Result res;

	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS) {
	    errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
	}

	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS) {
	    errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res, origin);
	}
}

static void terminate_tee_session(struct secure_storage_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

int main()
{
    struct secure_storage_ctx ctx;

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

 * scp secure_storage/ta/ef83682b-8a80-45e0-9993-ae583a386628.ta wenshuyu@192.168.1.6:/lib/optee_armtz
 * scp secure_storage/host/secure_storage wenshuyu@192.168.1.6:/usr/bin
 */

