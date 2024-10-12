#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tee_client_api.h>

#include "../ta/include/aes_cmac.h"

const char *message = "hello world\n";

#define BUFFER_LEN 256
#define MAC_LEN (16)

struct aes_cmac_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
	uint8_t mac[MAC_LEN];
};

static void generate_key(struct aes_cmac_ctx *ctx)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;
	uint32_t key_len;
	uint8_t key[BUFFER_LEN] = {0};

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
									TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = key;
	op.params[0].tmpref.size = BUFFER_LEN;

	res = TEEC_InvokeCommand(&ctx->sess, AES_CMAC_GEN_KEY, &op, &err_origin);
	if(res != TEEC_SUCCESS) {
		errx(1, "generate key failed\n");
	}

	key_len = op.params[0].tmpref.size;

	printf("key is :\n");
	for(uint16_t i = 0; i < key_len; i++) {
		printf("%02x", key[i]);
	}
	printf("\n\n");
}

static void do_mac(struct aes_cmac_ctx *ctx)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
									TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)message;
	op.params[0].tmpref.size = strlen(message);
	op.params[1].tmpref.buffer = ctx->mac;
	op.params[1].tmpref.size = MAC_LEN;

	res = TEEC_InvokeCommand(&ctx->sess, AES_CMAC_GEN_MAC, &op, &err_origin);
	if(res != TEEC_SUCCESS) {
		errx(1, "do mac failed\n");
	}

	uint32_t mac_len = op.params[1].tmpref.size;
	printf("MAC is :\n");
	for(uint16_t i = 0; i < mac_len; i++) {
		printf("%02x", ctx->mac[i]);;
	}
	printf("\n\n");
}

static void verify(struct aes_cmac_ctx *ctx)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
									TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)message;
	op.params[0].tmpref.size = strlen(message);
	op.params[1].tmpref.buffer = ctx->mac;
	op.params[1].tmpref.size = MAC_LEN;

	res = TEEC_InvokeCommand(&ctx->sess, AES_CMAC_VERIFY, &op, &err_origin);
	if(res != TEEC_SUCCESS) {
		errx(1, "verify failed\n");
	}
}

static void prepare_tee_session(struct aes_cmac_ctx *ctx)
{
	TEEC_UUID uuid = TA_AES_CMAC_UUID;
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

static void example(struct aes_cmac_ctx *ctx)
{
	generate_key(ctx);
	do_mac(ctx);
	verify(ctx);
}

static void terminate_tee_session(struct aes_cmac_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

int main()
{
    struct aes_cmac_ctx ctx;

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

 * scp aes_cmac/ta/d0ae44a0-6a59-4be3-af7e-19386316cd3f.ta wenshuyu@192.168.1.6:/lib/optee_armtz
 * scp aes_cmac/host/aes_cmac wenshuyu@192.168.1.6:/usr/bin
 */

