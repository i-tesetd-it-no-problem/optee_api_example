#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tee_client_api.h>

#include "../ta/include/aes_xts.h"

const char *plain_src = "hello world hello world\n"; // plain text size must > 16(a block)

#define BUFFER_LEN 256
#define IV_SIZE 16

uint8_t cipher_buf[BUFFER_LEN] = {0};
uint16_t cipher_len;

struct aes_xts_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
	uint8_t iv[IV_SIZE];
};

static void generate_key(struct aes_xts_ctx *ctx)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;
	uint32_t key1_len;
	uint8_t key1[BUFFER_LEN] = {0};

	uint32_t key2_len;
	uint8_t key2[BUFFER_LEN] = {0};

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT,
									TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = key1;
	op.params[0].tmpref.size = BUFFER_LEN;
	op.params[1].tmpref.buffer = key2;
	op.params[1].tmpref.size = BUFFER_LEN;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_XTS_GEN_KEY, &op, &err_origin);
	if(res != TEEC_SUCCESS) {
		errx(1, "generate key failed\n");
	}

	key1_len = op.params[0].tmpref.size;
	printf("key1 is :\n");
	for(uint16_t i = 0; i < key1_len; i++) {
		printf("%02x", key1[i]);
	}
	printf("\n\n");

	key2_len = op.params[1].tmpref.size;
	printf("key2 is :\n");
	for(uint16_t i = 0; i < key2_len; i++) {
		printf("%02x", key2[i]);
	}
	printf("\n\n");
}

static void generate_iv(struct aes_xts_ctx *ctx)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
									TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = ctx->iv;
	op.params[0].tmpref.size = IV_SIZE;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_XTS_GEN_IV, &op, &err_origin);
	if(res != TEEC_SUCCESS) {
		errx(1, "generate iv failed\n");
	}

	printf("IV is :\n");
	for(uint16_t i = 0; i < IV_SIZE; i++) {
		printf("%02x", ctx->iv[i]);
	}
	printf("\n\n");
}

static void encrypt(struct aes_xts_ctx *ctx)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
									TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)plain_src;
	op.params[0].tmpref.size = strlen(plain_src);
	op.params[1].tmpref.buffer = ctx->iv;
	op.params[1].tmpref.size = IV_SIZE;
	op.params[2].tmpref.buffer = (void *)cipher_buf;
	op.params[2].tmpref.size = BUFFER_LEN;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_XTS_ENCRYPT, &op, &err_origin);
	if(res != TEEC_SUCCESS) {
		errx(1, "encrypt failed\n");
	}

	cipher_len = op.params[2].tmpref.size;
	printf("cipher text is :\n");
	for(uint16_t i = 0; i < cipher_len; i++) {
		printf("%02x", cipher_buf[i]);;
	}
	printf("\n\n");
}

static void decrypt(struct aes_xts_ctx *ctx)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;
	uint32_t plain_len;
	uint8_t plain_buf[BUFFER_LEN];

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
									TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
	op.params[0].tmpref.buffer = cipher_buf;
	op.params[0].tmpref.size = cipher_len;
	op.params[1].tmpref.buffer = ctx->iv;
	op.params[1].tmpref.size = IV_SIZE;
	op.params[2].tmpref.buffer = plain_buf;
	op.params[2].tmpref.size = BUFFER_LEN;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_XTS_DECRYPT, &op, &err_origin);
	if(res != TEEC_SUCCESS) {
		errx(1, "decrypt failed\n");
	}

	plain_len = op.params[2].tmpref.size;
	printf("plain text is :\n");
	for(uint16_t i = 0; i < plain_len; i++) {
		printf("%c", plain_buf[i]);;
	}
	printf("\n\n");
}

static void prepare_tee_session(struct aes_xts_ctx *ctx)
{
	TEEC_UUID uuid = TA_AES_XTS_UUID;
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

static void example(struct aes_xts_ctx *ctx)
{
	generate_key(ctx);
	generate_iv(ctx);
	encrypt(ctx);
	decrypt(ctx);
}

static void terminate_tee_session(struct aes_xts_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

int main()
{
    struct aes_xts_ctx ctx;

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

 * scp aes_xts/ta/e53ba603-3110-4fac-94bc-c8d7e37ea26e.ta wenshuyu@192.168.1.6:/lib/optee_armtz
 * scp aes_xts/host/aes_xts wenshuyu@192.168.1.6:/usr/bin
 */

