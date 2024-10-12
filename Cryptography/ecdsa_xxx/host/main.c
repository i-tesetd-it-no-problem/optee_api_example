#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tee_client_api.h>

#include "../ta/include/ecdsa_xxx.h"

#define BUFFER_SIZE (256)

char *message = "hello world";

struct ecdsa_xxx_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
	uint8_t digest[DIGEST_BITS / 8];
	uint8_t signature[KEYPAIR_SIZE * 2];
	uint32_t signature_len;
};

static void generate_key(struct ecdsa_xxx_ctx *ctx)
{
	TEEC_Operation op;
	uint32_t error_origin;
	TEEC_Result res;
	uint8_t pub_key[BUFFER_SIZE];

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
										TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = pub_key;
	op.params[0].tmpref.size = BUFFER_SIZE;

	res = TEEC_InvokeCommand(&ctx->sess, ECDSA_XXX_GEN_KEY, &op, &error_origin);
	if(res != TEEC_SUCCESS) 
		errx(1, "generate key pair failed\n");
	
	printf("generate keypair successful\n\n");
}

static void digest(struct ecdsa_xxx_ctx *ctx)
{
	TEEC_Operation op;
	uint32_t error_origin;
	TEEC_Result res;
	uint32_t i;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
										TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = message;
	op.params[0].tmpref.size = strlen(message);
	op.params[1].tmpref.buffer = ctx->digest;
	op.params[1].tmpref.size = DIGEST_BITS / 8;

	res = TEEC_InvokeCommand(&ctx->sess, ECDSA_XXX_DIGEST, &op, &error_origin);
	if(res != TEEC_SUCCESS) 
		errx(1, "digest failed\n");
	
	uint32_t digest_size = op.params[1].tmpref.size;
	printf("digestis :\n");
	for(i = 0; i < digest_size; i++) {
		printf("%02x", ctx->digest[i]);
	}
	printf("\n\n");
}

static void sign(struct ecdsa_xxx_ctx *ctx)
{
	TEEC_Operation op;
	uint32_t error_origin;
	TEEC_Result res;
	uint32_t i;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
										TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = ctx->digest;
	op.params[0].tmpref.size = DIGEST_BITS / 8;
	op.params[1].tmpref.buffer = ctx->signature;
	op.params[1].tmpref.size = KEYPAIR_SIZE * 2;

	res = TEEC_InvokeCommand(&ctx->sess, ECDSA_XXX_SIGN, &op, &error_origin);
	if(res != TEEC_SUCCESS) 
		errx(1, "sign failed\n");
	
	ctx->signature_len = op.params[1].tmpref.size;
	printf("signature :\n");
	for(i = 0; i < ctx->signature_len; i++) {
		printf("%02x", ctx->signature[i]);
	}
	printf("\n\n");
}

static void verify(struct ecdsa_xxx_ctx *ctx)
{
	TEEC_Operation op;
	uint32_t error_origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
										TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = ctx->digest;
	op.params[0].tmpref.size = DIGEST_BITS / 8;
	op.params[1].tmpref.buffer = ctx->signature;
	op.params[1].tmpref.size = ctx->signature_len;

	res = TEEC_InvokeCommand(&ctx->sess, ECDSA_XXX_VERIFY, &op, &error_origin);
	if(res != TEEC_SUCCESS) 
		errx(1, "verify failed\n");
}

static void example(struct ecdsa_xxx_ctx *ctx)
{
	generate_key(ctx);
	digest(ctx);
	sign(ctx);
	verify(ctx);
}

static void prepare_tee_session(struct ecdsa_xxx_ctx *ctx)
{
	TEEC_UUID uuid = TA_ECDSA_XXX_UUID;
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

static void terminate_tee_session(struct ecdsa_xxx_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

int main()
{
    struct ecdsa_xxx_ctx ctx;

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

 * scp ecdsa_xxx/ta/ad3fae37-3956-48fe-86b3-a6f9135a87cb.ta wenshuyu@192.168.1.6:/lib/optee_armtz
 * scp ecdsa_xxx/host/ecdsa_xxx wenshuyu@192.168.1.6:/usr/bin
 */

