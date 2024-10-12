#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tee_client_api.h>

#include "../ta/include/secure_storage_01.h"

const char *save_data = "secure storage 01 test"; // 写入的数据
const char *object_name = "secure_storage_01"; // 存储对象名

struct secure_storage_01_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
	const char *object_id; // 存储对象名
	size_t object_id_size; // 存储对象名大小 strlen + 1
};

void prepare_tee_session(struct secure_storage_01_ctx *ctx)
{
	TEEC_UUID uuid = TA_SECURE_STORAGE_01_UUID;
	uint32_t origin;
	TEEC_Result res;

	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS) {
	    printf("TEEC_InitializeContext failed with code 0x%x", res);
	    exit(0);
	}

	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS) {
	    printf("TEEC_Opensession failed with code 0x%x origin 0x%x", res, origin);
	    exit(0);
	}
}

void terminate_tee_session(struct secure_storage_01_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

static void create_persistant_object(struct secure_storage_01_ctx *ctx)
{
	TEEC_Operation op;
	uint32_t origin_error;
	TEEC_Result ret;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)ctx->object_id;
	op.params[0].tmpref.size = ctx->object_id_size;
	op.params[1].value.a = strlen(save_data) + 1;

	ret = TEEC_InvokeCommand(&ctx->sess, TA_SECURE_STORAGE_01_CMD_CREATE_OBJECT, &op, &origin_error);
	if(ret != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed with code 0x%x origin 0x%x", ret, origin_error);
		exit(0);
	}

	printf("Object created\n");
}

static void update_persistant_object(struct secure_storage_01_ctx *ctx)
{
	TEEC_Operation op;
	uint32_t origin_error;
	TEEC_Result ret;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)ctx->object_id; // 参数一 存储对象名
	op.params[0].tmpref.size = ctx->object_id_size;
	op.params[1].tmpref.buffer = (void *)save_data; // 参数二 写入的数据
	op.params[1].tmpref.size = strlen(save_data) + 1;

	ret = TEEC_InvokeCommand(&ctx->sess, TA_SECURE_STORAGE_01_CMD_UPDATE_OBJECT, &op, &origin_error);
	if(ret != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed with code 0x%x origin 0x%x", ret, origin_error);
		exit(0);
	}

	printf("Object updated\n");
}

static void read_persistant_object(struct secure_storage_01_ctx *ctx)
{
	TEEC_Operation op;
	uint32_t origin_error;
	TEEC_Result ret;
	size_t read_size = 0;
	char read_data[256] = {0};

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)ctx->object_id; // 参数一 存储对象名
	op.params[0].tmpref.size = ctx->object_id_size;
	op.params[1].tmpref.buffer = read_data; // 参数二 读取的数据buffer
	op.params[1].tmpref.size = strlen(save_data) + 1; // 参数二 读取的数据buffer大小

	ret = TEEC_InvokeCommand(&ctx->sess, TA_SECURE_STORAGE_01_CMD_READ_OBJECT, &op, &origin_error);
	if(ret != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed with code 0x%x origin 0x%x", ret, origin_error);
		exit(0);
	}

	read_size = op.params[1].tmpref.size;  // 实际读取的数据大小

	printf("\nRead data: %s\nRead size: %d\n\n", read_data, read_size);
}

static void delete_persistant_object(struct secure_storage_01_ctx *ctx)
{
	TEEC_Operation op;
	uint32_t origin_error;
	TEEC_Result ret;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)ctx->object_id; // 参数一 存储对象名
	op.params[0].tmpref.size = ctx->object_id_size;

	ret = TEEC_InvokeCommand(&ctx->sess, TA_SECURE_STORAGE_01_CMD_DELETE_OBJECT, &op, &origin_error);
	if(ret != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed with code 0x%x origin 0x%x", ret, origin_error);
		exit(0);
	}

	printf("Object deleted\n");
}

int main()
{
    struct secure_storage_01_ctx ctx;

	ctx.object_id = object_name; // 存储对象名
	ctx.object_id_size = strlen(object_name) + 1; // 存储对象名大小 strlen + 1

    prepare_tee_session(&ctx);

	create_persistant_object(&ctx); // 创建持久化对象

	update_persistant_object(&ctx); // 更新持久化对象

	read_persistant_object(&ctx); // 读取持久化对象

	delete_persistant_object(&ctx); // 删除持久化对象

    terminate_tee_session(&ctx);

    return 0;
}
