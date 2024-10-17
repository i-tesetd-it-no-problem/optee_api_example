/* 自动生成的密钥数组和大小宏定义，用于测试密钥交换算法 请勿修改 */
#ifndef _DH_KEYS_H
#define _DH_KEYS_H

#include <stdint.h>

#define CA_ECDH_P192_PRIVATE_KEY_SIZE 113  /* CA侧私钥大小 */
#define CA_ECDH_P192_PUBLIC_KEY_SIZE 49   /* CA侧公钥大小 */

#define CA_ECDH_P224_PRIVATE_KEY_SIZE 122  /* CA侧私钥大小 */
#define CA_ECDH_P224_PUBLIC_KEY_SIZE 57   /* CA侧公钥大小 */

#define CA_ECDH_P256_PRIVATE_KEY_SIZE 138  /* CA侧私钥大小 */
#define CA_ECDH_P256_PUBLIC_KEY_SIZE 65   /* CA侧公钥大小 */

#define CA_ECDH_P384_PRIVATE_KEY_SIZE 185  /* CA侧私钥大小 */
#define CA_ECDH_P384_PUBLIC_KEY_SIZE 97   /* CA侧公钥大小 */

#define CA_ECDH_P521_PRIVATE_KEY_SIZE 241  /* CA侧私钥大小 */
#define CA_ECDH_P521_PUBLIC_KEY_SIZE 133   /* CA侧公钥大小 */

#define CA_X25519_PRIVATE_KEY_SIZE 32  /* CA侧私钥大小 */
#define CA_X25519_PUBLIC_KEY_SIZE 32   /* CA侧公钥大小 */


extern uint8_t ca_ecdh_p192_private_key[CA_ECDH_P192_PRIVATE_KEY_SIZE];
extern uint8_t ca_ecdh_p192_public_key[CA_ECDH_P192_PUBLIC_KEY_SIZE];

extern uint8_t ca_ecdh_p224_private_key[CA_ECDH_P224_PRIVATE_KEY_SIZE];
extern uint8_t ca_ecdh_p224_public_key[CA_ECDH_P224_PUBLIC_KEY_SIZE];

extern uint8_t ca_ecdh_p256_private_key[CA_ECDH_P256_PRIVATE_KEY_SIZE];
extern uint8_t ca_ecdh_p256_public_key[CA_ECDH_P256_PUBLIC_KEY_SIZE];

extern uint8_t ca_ecdh_p384_private_key[CA_ECDH_P384_PRIVATE_KEY_SIZE];
extern uint8_t ca_ecdh_p384_public_key[CA_ECDH_P384_PUBLIC_KEY_SIZE];

extern uint8_t ca_ecdh_p521_private_key[CA_ECDH_P521_PRIVATE_KEY_SIZE];
extern uint8_t ca_ecdh_p521_public_key[CA_ECDH_P521_PUBLIC_KEY_SIZE];

extern uint8_t ca_x25519_private_key[CA_X25519_PRIVATE_KEY_SIZE];
extern uint8_t ca_x25519_public_key[CA_X25519_PUBLIC_KEY_SIZE];

#endif /* _DH_KEYS_H */
