#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tee_client_api.h>

#include "../ta/include/rsaes_pkcs1_oaep_mgf1_xxx.h"

const char *plain_src = "hello world hello world\n";

#define BUFFER_SIZE 256

uint8_t cipher_buf[BUFFER_SIZE] = {0};
uint16_t cipher_len;

struct rsaes_pkcs1_v1_5_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

static void generate_key(struct rsaes_pkcs1_v1_5_ctx *ctx)
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

	res = TEEC_InvokeCommand(&ctx->sess, RSAES_PKCS1_OAEP_MGF1_GEN_KEY, &op, &error_origin);
	if(res != TEEC_SUCCESS) 
		errx(1, "generate key pair failed\n");
	
	printf("generate keypair successful\n\n");
}

static void encrypt(struct rsaes_pkcs1_v1_5_ctx *ctx)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
									TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)plain_src;
	op.params[0].tmpref.size = strlen(plain_src);
	op.params[1].tmpref.buffer = (void *)cipher_buf;
	op.params[1].tmpref.size = BUFFER_SIZE;

	res = TEEC_InvokeCommand(&ctx->sess, RSAES_PKCS1_OAEP_MGF1_ENCRYPT, &op, &err_origin);
	if(res != TEEC_SUCCESS) {
		errx(1, "encrypt failed\n");
	}

	cipher_len = op.params[1].tmpref.size;
	printf("cipher text is :\n");
	for(uint16_t i = 0; i < cipher_len; i++) {
		printf("%02x", cipher_buf[i]);;
	}
	printf("\n\n");
}

static void decrypt(struct rsaes_pkcs1_v1_5_ctx *ctx)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;
	uint32_t plain_len;
	uint8_t plain_buf[BUFFER_SIZE];

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
									TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = cipher_buf;
	op.params[0].tmpref.size = cipher_len;
	op.params[1].tmpref.buffer = plain_buf;
	op.params[1].tmpref.size = BUFFER_SIZE;

	res = TEEC_InvokeCommand(&ctx->sess, RSAES_PKCS1_OAEP_MGF1_DECRYPT, &op, &err_origin);
	if(res != TEEC_SUCCESS) {
		errx(1, "decrypt failed\n");
	}

	plain_len = op.params[1].tmpref.size;
	printf("plain text is :\n");
	for(uint16_t i = 0; i < plain_len; i++) {
		printf("%c", plain_buf[i]);;
	}
	printf("\n\n");
}

static void prepare_tee_session(struct rsaes_pkcs1_v1_5_ctx *ctx)
{
	TEEC_UUID uuid = TA_RSAES_PKCS1_OAEP_MGF1_XXX_UUID;
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

static void example(struct rsaes_pkcs1_v1_5_ctx *ctx)
{
	generate_key(ctx);
	encrypt(ctx);
	decrypt(ctx);
}

static void terminate_tee_session(struct rsaes_pkcs1_v1_5_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

int main()
{
    struct rsaes_pkcs1_v1_5_ctx ctx;

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

 * scp rsaes_pkcs1_oaep_mgf1_xxx/ta/0cfa47d1-216b-4286-ac1c-086d6a7e558b.ta wenshuyu@192.168.1.6:/lib/optee_armtz
 * scp rsaes_pkcs1_oaep_mgf1_xxx/host/rsaes_pkcs1_oaep_mgf1_xxx wenshuyu@192.168.1.6:/usr/bin
 */
