#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tee_client_api.h>

#include "../ta/include/rng.h"

struct rng_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

static void rng_test(struct rng_ctx *ctx)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;
	uint32_t buf_size = 16;
	uint8_t buf[16];

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = buf;
	op.params[0].tmpref.size = buf_size;

	res = TEEC_InvokeCommand(&ctx->sess, GENERATE_RANDOM, &op, &err_origin);
	if (res != TEEC_SUCCESS) {
	    errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
	}

	printf("Random number: ");
	for (int i = 0; i < buf_size; i++) {
	    printf("%02x", buf[i]);
	}
	printf("\n");
}

static void prepare_tee_session(struct rng_ctx *ctx)
{
	TEEC_UUID uuid = TA_RNG_UUID;
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

static void terminate_tee_session(struct rng_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

int main()
{
    struct rng_ctx ctx;

    prepare_tee_session(&ctx);

    rng_test(&ctx);

    terminate_tee_session(&ctx);

    return 0;
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

