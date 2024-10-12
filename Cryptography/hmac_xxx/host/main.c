#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tee_client_api.h>

#include "../ta/include/hmac_xxx.h"

#define MAC_LEN (MAC_BITS / 8)

struct hmac_xxx_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

/**
 * @brief HMAC算法案例
 * 
 * @param ctx 会话上下文
 * @param alg 算法类型
 */
static void hmac_xxx_example(struct hmac_xxx_ctx *ctx)
{
	TEEC_Operation op;
	TEEC_Result ret;
	uint32_t error_origin;
	uint16_t i;
	char *origin_data = "Hello World";
	uint8_t key[MAC_LEN] = {0};
	uint8_t mac[MAC_LEN] = {0};

	// generate key
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = key;
	op.params[0].tmpref.size = MAC_LEN;

	ret = TEEC_InvokeCommand(&ctx->sess, HMAC_XXX_GEN_KEY, &op, &error_origin);
	if(ret != TEEC_SUCCESS) 
		errx(1, "generate key failed\n");

	printf("random key is :\n");
	for(i = 0; i < op.params[0].tmpref.size; i++) 
		printf("%02x", key[i]);
	printf("\n\n");

	// generate mac
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = origin_data;
	op.params[0].tmpref.size = strlen(origin_data);
	op.params[1].tmpref.buffer = mac;
	op.params[1].tmpref.size = MAC_LEN;

	ret = TEEC_InvokeCommand(&ctx->sess, HMAC_XXX_GEN_MAC, &op, &error_origin);
	if(ret != TEEC_SUCCESS)
		errx(1, "generate mac failed\n");

	printf("MAC is :\n");
	for(i = 0; i < op.params[1].tmpref.size; i++) 
		printf("%02x", mac[i]);
	printf("\n\n");

	// verify mac
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = origin_data;
	op.params[0].tmpref.size = strlen(origin_data);
	op.params[1].tmpref.buffer = mac;
	op.params[1].tmpref.size = MAC_LEN;

	ret = TEEC_InvokeCommand(&ctx->sess, HMAC_XXX_VERIFY_MAC, &op, &error_origin);
	if(ret != TEEC_SUCCESS)
		errx(1, "verify mac failed\n");

	printf("verify success\n");
}

static void prepare_tee_session(struct hmac_xxx_ctx *ctx)
{
	TEEC_UUID uuid = TA_HMAC_XXX_UUID;
	uint32_t origin;
	TEEC_Result res;

	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS) {
	    printf("TEEC_InitializeContext failed with code 0x%x\n", res);
	    exit(0);
	}

	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS) {
	    printf("TEEC_Opensession failed with code 0x%x origin 0x%x\n", res, origin);
	    exit(0);
	}
}

static void terminate_tee_session(struct hmac_xxx_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

int main()
{
    struct hmac_xxx_ctx ctx;

    prepare_tee_session(&ctx);

	hmac_xxx_example(&ctx);

    terminate_tee_session(&ctx);

    return 0;
}


/**
 * @brief 配置到开发板指令

 * 注意: 开发本需提前配置好SSH环境, 
 * 根文件系统也需要支持OPTEE, buildroot自行配置

 * /lib/optee_armtz 是OPTEE寻找TA的默认地址
 * /usr/bin 让CA目标文件可以直接当作命令运行

 * scp hmac_xxx/ta/d443b788-5283-498b-9940-5ee5f92f6a45.ta wenshuyu@192.168.1.6:/lib/optee_armtz
 * scp hmac_xxx/host/hmac_xxx wenshuyu@192.168.1.6:/usr/bin
 */

