#ifndef _DSA_SHAX_H
#define _DSA_SHAX_H

/***************************************************************** */

#define USE_DSA_ALGORITHM         TEE_ALG_DSA_SHA256
#define USE_DIGEST_ALGORITHM      TEE_ALG_SHA256
#define DIGEST_BITS               (256)
#define KEYPAIR_SIZE              (256) // 2048 bits
#define KEYPAIR_BITS              (KEYPAIR_SIZE * 8)
#define SIGNATURE_SIZE            (2 * (DIGEST_BITS / 8)) // 64 bytes

#define DSA_PRIME_SIZE            256
#define DSA_SUBPRIME_SIZE         32
#define DSA_BASE_SIZE             256
#define DSA_PUB_VALUE_SIZE        256
#define DSA_PRIV_VALUE_SIZE       32


/***************************************************************** */

enum dsa_components {
    DSA_PRIME,
    DSA_SUBPRIME,
    DSA_BASE,
    DSA_PUB_VALUE,
    DSA_PRIV_VALUE,

    DSA_COMPONENTS_MAX
};

#define TA_DSA_SHAX_UUID \
    { 0x9db4bf13, 0x7706, 0x4ef9, \
        { 0x8a, 0xc3, 0xe3, 0x8b, 0x82, 0x0b, 0x03, 0xd0} }

/* 
 * @brief : set keypair part 0
 *
 * param[0] (memref-input) dsa prime
 * param[1] (memref-input) dsa subprime
 * param[2] (memref-input) dsa base
 * param[3] (unused)
 */
#define DSA_SHA256_SET_KEY_0     0

/* 
 * @brief : set keypair part 1
 *
 * param[0] (memref-input) public key
 * param[1] (memref-input) private key
 * param[2] (unused)
 * param[3] (unused)
 */
#define DSA_SHA256_SET_KEY_1     1

/* 
 * @brief : digest
 *
 * param[0] (memref-input)     : message
 * param[1] (memref-output)    : digest
 * param[2] (unused)
 * param[3] (unused)
 */
#define DSA_SHA256_DIGEST        2

/* 
 * @brief : generate signature
 *
 * param[0] (memref-input)     : digest
 * param[1] (memref-output)    : signature
 * param[2] (unused)
 * param[3] (unused)
 */
#define DSA_SHA256_SIGN           3

/* 
 * @brief : verify signature
 *
 * param[0] (memref-input)     : digest
 * param[1] (memref-input)    : signature
 * param[2] (unused)
 * param[3] (unused)
 */
#define DSA_SHA256_VERIFY         4

#endif /* _DSA_SHAX_H */
