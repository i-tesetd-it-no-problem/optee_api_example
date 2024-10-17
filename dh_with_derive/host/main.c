#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tee_client_api.h>

#include "../ta/include/dh_with_derive.h"
#include "../dh_keys.h"

// 由python脚本 gen_dh_keypair.py 自动生成的公钥数组
uint8_t* pub_keys[DH_ALGORITHM_TYPE_MAX] = {
	[DH_ALGORITHM_TYPE_ECDH_P192] = ca_ecdh_p192_public_key,
	[DH_ALGORITHM_TYPE_ECDH_P224] = ca_ecdh_p224_public_key,
	[DH_ALGORITHM_TYPE_ECDH_P256] = ca_ecdh_p256_public_key,
	[DH_ALGORITHM_TYPE_ECDH_P384] = ca_ecdh_p384_public_key,
	[DH_ALGORITHM_TYPE_ECDH_P521] = ca_ecdh_p521_public_key,
	[DH_ALGORITHM_TYPE_X25519] = ca_x25519_public_key,
};

// 每个数组的大小
size_t pub_key_size[DH_ALGORITHM_TYPE_MAX] = {
	[DH_ALGORITHM_TYPE_ECDH_P192] = CA_ECDH_P192_PUBLIC_KEY_SIZE,
	[DH_ALGORITHM_TYPE_ECDH_P224] = CA_ECDH_P224_PUBLIC_KEY_SIZE,
	[DH_ALGORITHM_TYPE_ECDH_P256] = CA_ECDH_P256_PUBLIC_KEY_SIZE,
	[DH_ALGORITHM_TYPE_ECDH_P384] = CA_ECDH_P384_PUBLIC_KEY_SIZE,
	[DH_ALGORITHM_TYPE_ECDH_P521] = CA_ECDH_P521_PUBLIC_KEY_SIZE,
	[DH_ALGORITHM_TYPE_X25519] = CA_X25519_PRIVATE_KEY_SIZE,
};

// 打印信息
const char *algo_msg[DH_ALGORITHM_TYPE_MAX] = {
	[DH_ALGORITHM_TYPE_ECDH_P192] = "ECDH_P192 Example",
	[DH_ALGORITHM_TYPE_ECDH_P224] = "ECDH_P224 Example",
	[DH_ALGORITHM_TYPE_ECDH_P256] = "ECDH_P256 Example",
	[DH_ALGORITHM_TYPE_ECDH_P384] = "ECDH_P384 Example",
	[DH_ALGORITHM_TYPE_ECDH_P521] = "ECDH_P521 Example",
	[DH_ALGORITHM_TYPE_X25519] = "X25519 Example",
};

struct dh_with_derive_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

// 发送公钥让CA派生共享密钥
static void dh_init(struct dh_with_derive_ctx *ctx, enum dh_algorithm_type algo)
{
	TEEC_Operation op;
	TEEC_Result ret;
	uint32_t error_origin;

	printf("\n----------------------------------------%s----------------------------------------\n\n", algo_msg[algo]);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = algo; // 算法
	op.params[1].tmpref.size = pub_key_size[algo];
	op.params[1].tmpref.buffer = pub_keys[algo]; // 发送CA的公钥

	ret = TEEC_InvokeCommand(&ctx->sess, DH_WITH_DERIVE_CMD_INIT, &op, &error_origin);
	if (ret != TEEC_SUCCESS) {
	    printf("TEEC_InvokeCommand failed with code 0x%x origin 0x%x\n", ret, error_origin);	
	    exit(0);
	}
	
	printf("\nta has generated key pair and derive the key by CA's public key\n\n");
}

static void get_ta_pub_key(struct dh_with_derive_ctx *ctx, enum dh_algorithm_type algo)
{
	TEEC_Operation op;
	TEEC_Result ret;
	uint32_t error_origin;
#define TA_PUB_BUF_SIZE 256
	uint8_t ta_pub_key_buf[TA_PUB_BUF_SIZE] = {0}; // 存储TA公钥

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	
	op.params[0].tmpref.size = TA_PUB_BUF_SIZE;
	op.params[0].tmpref.buffer = ta_pub_key_buf;
	ret = TEEC_InvokeCommand(&ctx->sess, DH_WITH_DERIVE_CMD_GET_TA_PUBLIC_KEY, &op, &error_origin);
	if (ret != TEEC_SUCCESS) {
	    printf("TEEC_InvokeCommand failed with code 0x%x origin 0x%x\n", ret, error_origin);	
	    exit(0);
	}

	size_t  ta_pub_key_size = op.params[0].tmpref.size;
	printf("TA's public key is :\n");
	for(uint8_t i = 0; i < ta_pub_key_size; i++) // 打印TA公钥
		printf("%02x", ta_pub_key_buf[i]);
	printf("\n\n");
}

static void get_ta_derive_key(struct dh_with_derive_ctx *ctx, enum dh_algorithm_type algo)
{
	TEEC_Operation op;
	TEEC_Result ret;
	uint32_t error_origin;
	uint8_t ta_derive_key_buf[128] = {0}; // 存储TA派生的共享密钥

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	
	op.params[0].tmpref.size = 128;
	op.params[0].tmpref.buffer = ta_derive_key_buf;
	ret = TEEC_InvokeCommand(&ctx->sess, DH_WITH_DERIVE_CMD_GET_DERIVE_KEY, &op, &error_origin);
	if (ret != TEEC_SUCCESS) {
	    printf("TEEC_InvokeCommand failed with code 0x%x origin 0x%x\n", ret, error_origin);	
	    exit(0);
	}

	size_t  ta_derive_key_size = op.params[0].tmpref.size;
	printf("TA derive key is :\n");
	for(uint8_t i = 0; i < ta_derive_key_size; i++)  // 打印TA派生的共享密钥
		printf("%02x", ta_derive_key_buf[i]);
	printf("\n\n");
}

static void dh_examples(struct dh_with_derive_ctx *ctx, enum dh_algorithm_type algo)
{
	dh_init(ctx, algo); // 发送公钥给TA让TA派生共享密钥

	get_ta_pub_key(ctx, algo); // 获取TA公钥

	get_ta_derive_key(ctx, algo); // 获取TA派生的共享密钥
}

static void prepare_tee_session(struct dh_with_derive_ctx *ctx)
{
	TEEC_UUID uuid = TA_DH_WITH_DERIVE_UUID;
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

static void terminate_tee_session(struct dh_with_derive_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

int main()
{
    struct dh_with_derive_ctx ctx;

    prepare_tee_session(&ctx);

	// 遍历所有算法案例
    for(enum dh_algorithm_type algo = DH_ALGORITHM_TYPE_ECDH_P192; algo < DH_ALGORITHM_TYPE_MAX; algo++)
		dh_examples(&ctx, algo);

	// dh_examples(&ctx, DH_ALGORITHM_TYPE_X25519); // 执行单个算法案例

    terminate_tee_session(&ctx);

    return 0;
}

