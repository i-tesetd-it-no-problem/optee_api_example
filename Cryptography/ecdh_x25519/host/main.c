#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <tee_client_api.h>

#include "../ta/include/ecdh_x25519.h"

struct ecdh_x25519_ctx {
    TEEC_Context ctx;
    TEEC_Session sess;
    uint8_t peer_pub_key[KEYPAIR_SIZE * 3];
};


static uint8_t hex_char_to_byte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    errx(1, "Invalid hex character: %c\n", c);
}

static void hex_string_to_bytes(const char *hex_str, uint8_t *byte_array, size_t byte_array_len) {
    size_t hex_str_len = strlen(hex_str);
    if (hex_str_len % 2 != 0 || hex_str_len / 2 > byte_array_len) {
        errx(1, "Invalid hex string length\n");
    }

    for (size_t i = 0; i < hex_str_len / 2; i++) {
        char high = hex_str[2 * i];
        char low = hex_str[2 * i + 1];
        if (!isxdigit(high) || !isxdigit(low)) 
            errx(1, "Hex string contains invalid characters\n");
        byte_array[i] = (hex_char_to_byte(high) << 4) | hex_char_to_byte(low);
    }
}

static void generate_keypair(struct ecdh_x25519_ctx *ctx) {
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t error_origin;

    memset(&op, 0, sizeof(op));

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_OUTPUT,
        TEEC_NONE,  
        TEEC_NONE,  
        TEEC_NONE);

    op.params[0].tmpref.buffer = ctx->peer_pub_key;
    op.params[0].tmpref.size = sizeof(ctx->peer_pub_key);

    res = TEEC_InvokeCommand(&ctx->sess, ECDH_X25519_GEN_DH_KEYPAIR, &op, &error_origin);
    if (res != TEEC_SUCCESS) {
        errx(1, "Failed to generate keypair, code 0x%x\n", res);
    }

    printf("\nAlice public key (Hex):\n");
    for (uint32_t i = 0; i < op.params[0].tmpref.size; i++) {
        printf("%02x", ctx->peer_pub_key[i]);
    }
    printf("\n\nPlease provide this public key to the Bob.\n\n");
}

static void generate_shared_key(struct ecdh_x25519_ctx *ctx) {
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t error_origin;

    printf("\nPlease input the Bob's public key (Hex):\n");
    
    char input_buffer[256];
    if (fgets(input_buffer, sizeof(input_buffer), stdin) == NULL) {
        errx(1, "Failed to read public key\n");
    }
    input_buffer[strcspn(input_buffer, "\n")] = '\0';

    if (strlen(input_buffer) != 64) {
        errx(1, "Invalid public key length. Expected 64 hex characters.\n");
    }

    for (size_t i = 0; i < 64; i++) {
        if (!isxdigit(input_buffer[i])) {
            errx(1, "Invalid character in public key.\n");
        }
    }

    uint8_t peer_public_key[32];
    hex_string_to_bytes(input_buffer, peer_public_key, sizeof(peer_public_key));

    memset(&op, 0, sizeof(op));

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, 
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE);

    op.params[0].tmpref.buffer = peer_public_key;
    op.params[0].tmpref.size = sizeof(peer_public_key);

    res = TEEC_InvokeCommand(&ctx->sess, ECDH_X25519_DERIVE_KEY, &op, &error_origin);
    if (res != TEEC_SUCCESS) {
        errx(1, "Failed to derive shared key, code 0x%x\n", res);
    }
}

static void send_cipher_text(struct ecdh_x25519_ctx *ctx) {
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t error_origin;
    uint8_t iv[16];
    char input_buffer[256];

    memset(iv, 0x5A, 16);

    printf("Please input the Bob's cipher text:\n");

    if (fgets(input_buffer, sizeof(input_buffer), stdin) == NULL) {
        errx(1, "Failed to read cipher text\n");
    }
    input_buffer[strcspn(input_buffer, "\n")] = '\0'; 

    size_t input_len = strlen(input_buffer);
    if (input_len % 2 != 0 || input_len > 256) {
        errx(1, "Invalid cipher text length.\n");
    }

    for (size_t i = 0; i < input_len; i++) {
        if (!isxdigit(input_buffer[i])) {
            errx(1, "Cipher text contains invalid characters.\n");
        }
    }

    size_t cipher_len = input_len / 2;
    uint8_t *cipher_text = malloc(cipher_len);
    if (!cipher_text) {
        errx(1, "Failed to allocate memory for cipher text\n");
    }
    hex_string_to_bytes(input_buffer, cipher_text, cipher_len);

    memset(&op, 0, sizeof(op));

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_NONE,
        TEEC_NONE);

    op.params[0].tmpref.buffer = cipher_text;
    op.params[0].tmpref.size = cipher_len;
    op.params[1].tmpref.buffer = iv;
    op.params[1].tmpref.size = 16;

    res = TEEC_InvokeCommand(&ctx->sess, ECDH_X25519_DECRYPT, &op, &error_origin);
    if (res != TEEC_SUCCESS) {
        free(cipher_text);
        errx(1, "Failed to decrypt shared, code 0x%x\n", res);
    }

    free(cipher_text);
}


static void dh_example(struct ecdh_x25519_ctx *ctx) {
    generate_keypair(ctx);
    generate_shared_key(ctx);
    send_cipher_text(ctx);
}

static void prepare_tee_session(struct ecdh_x25519_ctx *ctx) {
    TEEC_UUID uuid = TA_ECDH_X25519_UUID;
    uint32_t origin;
    TEEC_Result res;

    res = TEEC_InitializeContext(NULL, &ctx->ctx);
    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_InitializeContext failed with code 0x%x\n", res);
    }

    res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_OpenSession failed with code 0x%x origin 0x%x\n", res, origin);
    }
}

static void terminate_tee_session(struct ecdh_x25519_ctx *ctx) {
    TEEC_CloseSession(&ctx->sess);
    TEEC_FinalizeContext(&ctx->ctx);
}

int main() {
    struct ecdh_x25519_ctx ctx;

    prepare_tee_session(&ctx);

    dh_example(&ctx);

    terminate_tee_session(&ctx);

    return 0;
}

/**
 * @brief 配置到开发板指令

 * 注意: 开发本需提前配置好SSH环境, 
 * 根文件系统也需要支持OPTEE, buildroot自行配置

 * /lib/optee_armtz 是OPTEE寻找TA的默认地址
 * /usr/bin 让CA目标文件可以直接当作命令运行

 * scp ecdh_x25519/ta/d1364928-171d-419c-b7ca-e57d64869c28.ta wenshuyu@192.168.1.6:/lib/optee_armtz
 * scp ecdh_x25519/host/ecdh_x25519 wenshuyu@192.168.1.6:/usr/bin
 */

