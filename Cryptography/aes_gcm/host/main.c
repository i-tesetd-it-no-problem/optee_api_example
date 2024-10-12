#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tee_client_api.h>

#include "../ta/include/aes_gcm.h"

const char *plain_text = "hello world\n";

#define BUFFER_SZIE (256)
#define TAG_SIZE 	(16)
#define IV_SIZE 	(12)

uint8_t cipher_len;
uint8_t cipher_buf[BUFFER_SZIE];

struct aes_gcm_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
	uint8_t iv[IV_SIZE];
	uint8_t tag[TAG_SIZE];
};

static void generate_key(struct aes_gcm_ctx *ctx)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;
	uint32_t key_len;
	uint32_t iv_len;
	uint8_t key[BUFFER_SZIE] = {0};

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT,
									TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = key;
	op.params[0].tmpref.size = BUFFER_SZIE;
	op.params[1].tmpref.buffer = ctx->iv;
	op.params[1].tmpref.size = IV_SIZE;

	res = TEEC_InvokeCommand(&ctx->sess, AES_GCM_GEN_KEY, &op, &err_origin);
	if(res != TEEC_SUCCESS) {
		errx(1, "generate key failed\n");
	}

	key_len = op.params[0].tmpref.size;
	printf("key is :\n");
	for(uint16_t i = 0; i < key_len; i++) {
		printf("%02x", key[i]);
	}
	printf("\n\n");

	iv_len = op.params[1].tmpref.size;
	printf("iv is :\n");
	for(uint16_t i = 0; i < iv_len; i++) {
		printf("%02x", ctx->iv[i]);
	}
	printf("\n\n");
}

static void encrypt(struct aes_gcm_ctx *ctx)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
									TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT);
	op.params[0].tmpref.buffer = (void *)plain_text;
	op.params[0].tmpref.size = strlen(plain_text);
	op.params[1].tmpref.buffer = ctx->iv;
	op.params[1].tmpref.size = IV_SIZE;
	op.params[2].tmpref.buffer = cipher_buf;
	op.params[2].tmpref.size = BUFFER_SZIE;
	op.params[3].tmpref.buffer = ctx->tag;
	op.params[3].tmpref.size = TAG_SIZE;

	res = TEEC_InvokeCommand(&ctx->sess, AES_GCM_AE_ENCRYPR, &op, &err_origin);
	if(res != TEEC_SUCCESS) {
		errx(1, "encryptfailed\n");
	}

	cipher_len = op.params[2].tmpref.size;
	printf("cipher text is :\n");
	for(uint16_t i = 0; i < cipher_len; i++) {
		printf("%02x", cipher_buf[i]);;
	}
	printf("\n\n");

	uint32_t tag_len = op.params[3].tmpref.size;
	printf("tag is :\n");
	for(uint16_t i = 0; i < tag_len; i++) {
		printf("%02x", ctx->tag[i]);;
	}
	printf("\n\n");
}

static void decrypt(struct aes_gcm_ctx *ctx)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;
	uint32_t plain_len = 0;
	uint8_t plain_buf[BUFFER_SZIE];

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
									TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT);
	op.params[0].tmpref.buffer = cipher_buf;
	op.params[0].tmpref.size = cipher_len;
	op.params[1].tmpref.buffer = ctx->iv;
	op.params[1].tmpref.size = IV_SIZE;
	op.params[2].tmpref.buffer = plain_buf;
	op.params[2].tmpref.size = BUFFER_SZIE;
	op.params[3].tmpref.buffer = ctx->tag;
	op.params[3].tmpref.size = TAG_SIZE;

	res = TEEC_InvokeCommand(&ctx->sess, AES_GCM_AE_ENCRYPR, &op, &err_origin);
	if(res != TEEC_SUCCESS) {
		errx(1, "encryptfailed\n");
	}

	plain_len = op.params[2].tmpref.size;
	printf("plain text is :\n");
	for(uint16_t i = 0; i < plain_len; i++) {
		printf("%c", plain_buf[i]);;
	}
	printf("\n\n");
}

static void prepare_tee_session(struct aes_gcm_ctx *ctx)
{
	TEEC_UUID uuid = TA_AES_GCM_UUID;
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

static void example(struct aes_gcm_ctx *ctx)
{
	generate_key(ctx);
	encrypt(ctx);
	decrypt(ctx);
}

static void terminate_tee_session(struct aes_gcm_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

int main()
{
    struct aes_gcm_ctx ctx;

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

 * scp aes_gcm/ta/70eb931d-d838-4584-9124-cbe32031bb65.ta wenshuyu@192.168.1.6:/lib/optee_armtz
 * scp aes_gcm/host/aes_gcm wenshuyu@192.168.1.6:/usr/bin
 */

