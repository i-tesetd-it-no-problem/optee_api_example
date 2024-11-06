#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <tee_client_api.h>

#include "../ta/include/test_time.h"

struct time_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

static void get_systime(struct time_ctx *ctx)
{
	TEEC_Result res;
	uint32_t err_origin;
	TEEC_Operation op;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&ctx->sess, TIME_CMD_GET_SYSTIME, &op, &err_origin);
	if(res != TEEC_SUCCESS) {
		errx(1, "get systime failed with code 0x%x origin 0x%x", res, err_origin);
	}

	time_t timestamp = op.params[0].value.a;

	// convert timestamp to string
	char time_str[128];
	struct tm *tm_time = localtime(&timestamp);
	strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_time);

	printf("system time: %s\n", time_str);
}

static void wait(struct time_ctx *ctx)
{
	TEEC_Result res;
	uint32_t err_origin;
	TEEC_Operation op;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = WAIT_COUNTS; // wait 3s
	res = TEEC_InvokeCommand(&ctx->sess, TIME_CMD_TIME_WAIT, &op, &err_origin);
	if(res != TEEC_SUCCESS) {
		errx(1, "wait failed with code 0x%x origin 0x%x", res, err_origin);
	}
}

static void set_persistant_time(struct time_ctx *ctx)
{
	TEEC_Result res;
	uint32_t err_origin;
	TEEC_Operation op;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = TEST_TIMESTAMP; // timestamp
	op.params[0].value.b = 0; // reserved
	res = TEEC_InvokeCommand(&ctx->sess, TIME_CMD_SET_PERSISTANT_TIME, &op, &err_origin);
	if(res != TEEC_SUCCESS) {
		errx(1, "set persistant time failed with code 0x%x origin 0x%x", res, err_origin);
	}

	time_t persistant_time = TEST_TIMESTAMP;

	// convert timestamp to string
	char time_str[128];
	struct tm *tm_time = localtime(&persistant_time);
	strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_time);

	printf("set persistant time is : %s\n", time_str);
}

static void get_persistant_time(struct time_ctx *ctx)
{
	sleep(2);
	TEEC_Result res;
	uint32_t err_origin;
	TEEC_Operation op;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	res = TEEC_InvokeCommand(&ctx->sess, TIME_CMD_GET_PERSISTANT_TIME, &op, &err_origin);
	if(res != TEEC_SUCCESS) {
		errx(1, "set persistant time failed with code 0x%x origin 0x%x", res, err_origin);
	}

	time_t persistant_time = op.params[0].value.a;

	// convert timestamp to string
	char time_str[128];
	struct tm *tm_time = localtime(&persistant_time);
	strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_time);

	printf("update persistant time is : %s\n", time_str);
}

static void get_ree_time(struct time_ctx *ctx)
{
	TEEC_Result res;
	uint32_t err_origin;
	TEEC_Operation op;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	res = TEEC_InvokeCommand(&ctx->sess, TIME_CMD_GET_REE_TIME, &op, &err_origin);
	if(res != TEEC_SUCCESS) {
		errx(1, "get ree time failed with code 0x%x origin 0x%x", res, err_origin);
	}
}

static void example(struct time_ctx *ctx)
{
	get_systime(ctx);
	wait(ctx);
	set_persistant_time(ctx);
	get_persistant_time(ctx);
	get_ree_time(ctx);
}

static void prepare_tee_session(struct time_ctx *ctx)
{
	TEEC_UUID uuid = TA_TEST_TIME_UUID;
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

static void terminate_tee_session(struct time_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

int main()
{
    struct time_ctx ctx;

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

 * scp test_time/ta/13010e37-4220-4a0f-bb68-882f91d9349b.ta wenshuyu@192.168.1.6:/lib/optee_armtz
 * scp test_time/host/test_time wenshuyu@192.168.1.6:/usr/bin
 */

