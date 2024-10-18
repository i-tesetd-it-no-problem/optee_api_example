#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tee_client_api.h>

#include "../ta/include/sign_and_verify.h"

char *msg = "Hello, world!"; // 原始数据

char *example_info[SIGH_VERIFY_ALG_MAX] = {
	[SIGH_VERIFY_ALG_RSASSA_PKCSV1_5_SHA256] 		= "RSASSA_PKCS1_5_SHA256",
	[SIGH_VERIFY_ALG_RSASSA_PKCSV1_PSS_MGF1_SHA256] = "RSASSA_PKCS1_PSS_MGF1_SHA256",
	[SIGH_VERIFY_ALG_ECDSA_P256] 					= "EDCSA_P256",
	[SIGH_VERIFY_ALG_ED25519] 						= "ED25519",
};

// 摘要缓冲
#define DIGEST_LEN 256
size_t digest_len = DIGEST_LEN;
uint8_t digest_buffer[DIGEST_LEN] = {0};

// 签名缓冲
#define SIGN_LEN 512
size_t sign_len = SIGN_LEN;
uint8_t signature_buffer[SIGN_LEN] = {0};

struct sign_and_verify_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

// TA生成密钥
static void ta_gen_key(struct sign_and_verify_ctx *ctx, enum sigh_verify_alg alg)
{
	TEEC_Operation op;
	TEEC_Result ret;
	uint32_t error_orrgin;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = alg; // 算法类型

	ret = TEEC_InvokeCommand(&ctx->sess, SIGH_VERIFY_CMD_GENERATE_KEYPAIR, &op, &error_orrgin);
	if(ret != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed with code 0x%x origin 0x%x", ret, error_orrgin);
		exit(0);
	}
}

// 生成摘要
static void digest(struct sign_and_verify_ctx *ctx, enum sigh_verify_alg alg)
{
	TEEC_Operation op;
	TEEC_Result ret;
	uint32_t error_orrgin;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)msg;
	op.params[0].tmpref.size = strlen(msg) + 1;
	op.params[1].tmpref.buffer = (void *)digest_buffer;
	op.params[1].tmpref.size = DIGEST_LEN;
	if(alg == SIGH_VERIFY_ALG_ED25519)
		return;

	ret = TEEC_InvokeCommand(&ctx->sess, SIGH_VERIFY_CMD_DIGEST, &op, &error_orrgin);
	if(ret != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed with code 0x%x origin 0x%x", ret, error_orrgin);
		exit(0);
	}

	uint8_t *out = op.params[1].tmpref.buffer;
	digest_len = op.params[1].tmpref.size;
	printf("Digest is :\n");
	for(size_t i = 0; i < digest_len; i++)
		printf("%02x", out[i]);
	printf("\n\n");

}

// 对摘要签名
static void sign(struct sign_and_verify_ctx *ctx, enum sigh_verify_alg alg)
{
	TEEC_Operation op;
	TEEC_Result ret;
	uint32_t error_orrgin;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)digest_buffer;
	op.params[0].tmpref.size = digest_len;
	op.params[1].tmpref.buffer = (void *)signature_buffer;
	op.params[1].tmpref.size = SIGN_LEN;
	if(alg == SIGH_VERIFY_ALG_ED25519) {
		op.params[0].tmpref.buffer = (void *)msg;
		op.params[0].tmpref.size = strlen(msg) + 1;
	}

	ret = TEEC_InvokeCommand(&ctx->sess, SIGH_VERIFY_CMD_SIGN, &op, &error_orrgin);
	if(ret != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed with code 0x%x origin 0x%x", ret, error_orrgin);
		exit(0);
	}

	uint8_t *out = op.params[1].tmpref.buffer;
	sign_len = op.params[1].tmpref.size;
	printf("signature is :\n");
	for(size_t i = 0; i < sign_len; i++)
		printf("%02x", out[i]);
	printf("\n\n");
}

// 验证摘要
static void verify(struct sign_and_verify_ctx *ctx, enum sigh_verify_alg alg)
{
	TEEC_Operation op;
	TEEC_Result ret;
	uint32_t error_orrgin;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)digest_buffer;
	op.params[0].tmpref.size = digest_len;
	op.params[1].tmpref.buffer = (void *)signature_buffer;
	op.params[1].tmpref.size = sign_len;
	if(alg == SIGH_VERIFY_ALG_ED25519) {
		op.params[0].tmpref.buffer = (void *)msg;
		op.params[0].tmpref.size = strlen(msg) + 1;
	}

	ret = TEEC_InvokeCommand(&ctx->sess, SIGH_VERIFY_CMD_VERIFY, &op, &error_orrgin);
	if(ret != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed with code 0x%x origin 0x%x", ret, error_orrgin);
		exit(0);
	}
}

// 不同案例
static void test_sign_and_verify(struct sign_and_verify_ctx *ctx, enum sigh_verify_alg alg)
{
	printf("-----------------------------------------%s-----------------------------------------\n\n", example_info[alg]);
	ta_gen_key(ctx, alg);
	digest(ctx, alg);
	sign(ctx, alg);
	verify(ctx, alg);
	printf("\n");
}

static void prepare_tee_session(struct sign_and_verify_ctx *ctx)
{
	TEEC_UUID uuid = TA_SIGN_AND_VERIFY_UUID;
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

static void terminate_tee_session(struct sign_and_verify_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

int main()
{
    struct sign_and_verify_ctx ctx;

    prepare_tee_session(&ctx);

	for(enum sigh_verify_alg alg = SIGH_VERIFY_ALG_RSASSA_PKCSV1_5_SHA256; alg < SIGH_VERIFY_ALG_MAX; alg++)
		test_sign_and_verify(&ctx, alg);	

    terminate_tee_session(&ctx);

    return 0;
}

