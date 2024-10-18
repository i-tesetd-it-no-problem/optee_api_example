#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tee_client_api.h>

#include "../ta/include/asymmetric_cipher.h"

struct asymmetric_cipher_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

char *example_info[ASYMM_CIPHER_ALG_MAX] = {
	[ASYMM_CIPHER_ALG_RSAES_PKCS1_V1_5] = "RSAES_PKCS1_V1_5",
	[ASYMM_CIPHER_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256] = "RSAES_PKCS1_OAEP_MGF1_SHA256",
};

char *plain_text = "Asymmetric Cipher Example"; // 明文信息

size_t cipher_text_len = 256; // 密文长度
char cipher_text[256]; // 密文信息

// 生成密钥对
static void genereate_keypair(struct asymmetric_cipher_ctx *ctx, enum asymm_cipher_alg alg)
{
	TEEC_Operation op;
	TEEC_Result ret;
	uint32_t error_origin;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = alg; // 算法类型

	ret = TEEC_InvokeCommand(&ctx->sess, ASYMM_CIPHER_CMD_GEN, &op, &error_origin);
	if(ret != TEEC_SUCCESS) {
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", ret, error_origin);
	}
}

static void encrypt(struct asymmetric_cipher_ctx *ctx, enum asymm_cipher_alg alg)
{
	TEEC_Operation op;
	TEEC_Result ret;
	uint32_t error_origin;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)plain_text; // 明文信息
	op.params[0].tmpref.size = strlen(plain_text) + 1;
	op.params[1].tmpref.buffer = cipher_text;  // 密文信息
	op.params[1].tmpref.size = cipher_text_len;

	ret = TEEC_InvokeCommand(&ctx->sess, ASYMM_CIPHER_CMD_ENCRYP, &op, &error_origin);
	if(ret != TEEC_SUCCESS) {
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", ret, error_origin);
	}

	cipher_text_len = op.params[1].tmpref.size; // 密文长度

	printf("plain text is :%s\n", plain_text);
	printf("encrypted text:\n");
	for(int i = 0; i < cipher_text_len; i++) {
		printf("%02x", (unsigned char)cipher_text[i]);
	}
	printf("\n");
}

static void decrypt(struct asymmetric_cipher_ctx *ctx, enum asymm_cipher_alg alg)
{
	TEEC_Operation op;
	TEEC_Result ret;
	uint32_t error_origin;

	size_t plain_text_len = 256; // 明文长度
	uint8_t plain_text[256]; // 明文信息

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = cipher_text; // 密文信息
	op.params[0].tmpref.size = cipher_text_len;
	op.params[1].tmpref.buffer = plain_text; // 明文信息
	op.params[1].tmpref.size = plain_text_len;

	ret = TEEC_InvokeCommand(&ctx->sess, ASYMM_CIPHER_CMD_DECRYP, &op, &error_origin);
	if(ret != TEEC_SUCCESS) {
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", ret, error_origin);
	}

	printf("decrypted text:\n%s\n", plain_text);
}

// 非对称加密案例
static void asymmetric_cipher_example(struct asymmetric_cipher_ctx *ctx, enum asymm_cipher_alg alg)
{
	printf("------------------------------------%s------------------------------------\n",example_info[alg]);
	genereate_keypair(ctx, alg); 	// 生成密钥对
	encrypt(ctx, alg);  			// 加密
	decrypt(ctx, alg); 				// 解密
	printf("\n");
}

static void prepare_tee_session(struct asymmetric_cipher_ctx *ctx)
{
	TEEC_UUID uuid = TA_ASYMMETRIC_CIPHER_UUID;
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

static void terminate_tee_session(struct asymmetric_cipher_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

int main()
{
    struct asymmetric_cipher_ctx ctx;

    prepare_tee_session(&ctx);

    asymmetric_cipher_example(&ctx, ASYMM_CIPHER_ALG_RSAES_PKCS1_V1_5);
	asymmetric_cipher_example(&ctx, ASYMM_CIPHER_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256);

    terminate_tee_session(&ctx);

    return 0;
}

