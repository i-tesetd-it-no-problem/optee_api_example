#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <tee_client_api.h>

#include "../ta/include/dh_basic.h"

struct dh_basic_ctx {
    TEEC_Context ctx;
    TEEC_Session sess;
    uint8_t peer_pub_key[KEYPAIR_BYTES];
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

static void generate_keypair(struct dh_basic_ctx *ctx) {
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t error_origin;

    printf("\nPlease input dh_prime (Hex):\n");
    char dh_prime_input[2049];
    if (fgets(dh_prime_input, sizeof(dh_prime_input), stdin) == NULL) {
        errx(1, "Failed to read dh_prime\n");
    }
    dh_prime_input[strcspn(dh_prime_input, "\n")] = '\0';

    printf("\nPlease input dh_base (Hex):\n");
    char dh_base_input[513];
    if (fgets(dh_base_input, sizeof(dh_base_input), stdin) == NULL) {
        errx(1, "Failed to read dh_base\n");
    }
    dh_base_input[strcspn(dh_base_input, "\n")] = '\0';

    size_t dh_prime_len = strlen(dh_prime_input) / 2;
    uint8_t *dh_prime = malloc(dh_prime_len);
    if (!dh_prime) {
        errx(1, "Failed to allocate memory for dh_prime\n");
    }
    hex_string_to_bytes(dh_prime_input, dh_prime, dh_prime_len);

    size_t dh_base_len = strlen(dh_base_input) / 2;
    uint8_t *dh_base = malloc(dh_base_len);
    if (!dh_base) {
        free(dh_prime);
        errx(1, "Failed to allocate memory for dh_base\n");
    }
    hex_string_to_bytes(dh_base_input, dh_base, dh_base_len);

    memset(&op, 0, sizeof(op));

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_OUTPUT,
        TEEC_MEMREF_TEMP_INPUT,  
        TEEC_MEMREF_TEMP_INPUT,  
        TEEC_NONE);

    op.params[0].tmpref.buffer = ctx->peer_pub_key;
    op.params[0].tmpref.size = KEYPAIR_BYTES;
    op.params[1].tmpref.buffer = dh_prime;
    op.params[1].tmpref.size = dh_prime_len;
    op.params[2].tmpref.buffer = dh_base;
    op.params[2].tmpref.size = dh_base_len;

    res = TEEC_InvokeCommand(&ctx->sess, DH_BASIC_GEN_DH_KEYPAIR, &op, &error_origin);
    if (res != TEEC_SUCCESS) {
        free(dh_prime);
        free(dh_base);
        errx(1, "Failed to generate keypair, code 0x%x\n", res);
    }

    printf("\nAlice public key (Hex):\n");
    for (uint32_t i = 0; i < op.params[0].tmpref.size; i++) {
        printf("%02x", ctx->peer_pub_key[i]);
    }
    printf("\n\nPlease provide this public key to the Bob.\n\n");
    
    free(dh_prime);
    free(dh_base);
}

static void generate_shared_key(struct dh_basic_ctx *ctx) {
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t error_origin;
    
    printf("\nPlease input the Bob's public key (Hex):\n");
    char input_buffer[513]; 
    if (fgets(input_buffer, sizeof(input_buffer), stdin) == NULL) {
        errx(1, "Failed to read public key\n");
    }
    input_buffer[strcspn(input_buffer, "\n")] = '\0'; 

    size_t public_key_len = strlen(input_buffer) / 2;
    uint8_t *public_key = malloc(public_key_len);
    if (!public_key) {
        errx(1, "Failed to allocate memory for public key\n");
    }
    hex_string_to_bytes(input_buffer, public_key, public_key_len);

    memset(&op, 0, sizeof(op));

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, 
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE);

    op.params[0].tmpref.buffer = public_key;
    op.params[0].tmpref.size = public_key_len;
    
    res = TEEC_InvokeCommand(&ctx->sess, DH_BASIC_DERIVE_KEY, &op, &error_origin);
    if (res != TEEC_SUCCESS) {
        free(public_key);
        errx(1, "Failed to derive shared key, code 0x%x\n", res);
    }

    free(public_key);
}

static void send_cipher_text(struct dh_basic_ctx *ctx) {
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t error_origin;
	uint8_t iv[16];
	memset(iv, 0x5A, 16);
    
    printf("\nPlease input the Bob's cipher text:\n");
    char input_buffer[513]; 
    if (fgets(input_buffer, sizeof(input_buffer), stdin) == NULL) {
        errx(1, "Failed to read cipher text\n");
    }
    input_buffer[strcspn(input_buffer, "\n")] = '\0'; 

    size_t cipher_len = strlen(input_buffer) / 2;
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

    res = TEEC_InvokeCommand(&ctx->sess, DH_BASIC_DECRYPT, &op, &error_origin);
    if (res != TEEC_SUCCESS) {
        free(cipher_text);
        errx(1, "Failed to decrypt shared, code 0x%x\n", res);
    }

    free(cipher_text);
}

static void dh_example(struct dh_basic_ctx *ctx) {
    generate_keypair(ctx);
    generate_shared_key(ctx);
    send_cipher_text(ctx);
}

static void prepare_tee_session(struct dh_basic_ctx *ctx) {
    TEEC_UUID uuid = TA_DH_BASIC_UUID;
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

static void terminate_tee_session(struct dh_basic_ctx *ctx) {
    TEEC_CloseSession(&ctx->sess);
    TEEC_FinalizeContext(&ctx->ctx);
}

int main() {
    struct dh_basic_ctx ctx;

    prepare_tee_session(&ctx);

    dh_example(&ctx);

    terminate_tee_session(&ctx);

    return 0;
}
