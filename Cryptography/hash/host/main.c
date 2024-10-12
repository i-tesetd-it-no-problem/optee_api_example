#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tee_client_api.h>

#include "../ta/include/hash.h"

#define DIGEST_SIZE (DIGEST_BITS / 8)

char *message = "hello world";

struct hash_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

static void digest(struct hash_ctx *ctx)
{
	TEEC_Operation op;
	uint32_t error_origin;
	TEEC_Result res;
	uint8_t digest[DIGEST_SIZE];
	uint32_t i;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
										TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = message;
	op.params[0].tmpref.size = strlen(message);
	op.params[1].tmpref.buffer = digest;
	op.params[1].tmpref.size = DIGEST_SIZE;

	res = TEEC_InvokeCommand(&ctx->sess, HASH_DIGEST, &op, &error_origin);
	if(res != TEEC_SUCCESS) 
		errx(1, "digest failed\n");
	
	printf("orgin message is %s\n\n", message);

	uint32_t digest_size = op.params[1].tmpref.size;
	printf("digestis :\n");
	for(i = 0; i < digest_size; i++) {
		printf("%02x", digest[i]);
	}
	printf("\n\n");
}

static void prepare_tee_session(struct hash_ctx *ctx)
{
	TEEC_UUID uuid = TA_HASH_UUID;
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

static void terminate_tee_session(struct hash_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

int main()
{
    struct hash_ctx ctx;

    prepare_tee_session(&ctx);

    digest(&ctx);

    terminate_tee_session(&ctx);

    return 0;
}

/**
 * @brief 配置到开发板指令

 * 注意: 开发本需提前配置好SSH环境, 
 * 根文件系统也需要支持OPTEE, buildroot自行配置

 * /lib/optee_armtz 是OPTEE寻找TA的默认地址
 * /usr/bin 让CA目标文件可以直接当作命令运行

 * scp hash/ta/a4660423-4973-4f91-9bb6-882e7256e3ec.ta wenshuyu@192.168.1.6:/lib/optee_armtz
 * scp hash/host/hash wenshuyu@192.168.1.6:/usr/bin
 */

