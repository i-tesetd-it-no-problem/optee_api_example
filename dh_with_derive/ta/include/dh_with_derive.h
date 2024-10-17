// dh_with_derive.h

#ifndef _DH_WITH_DERIVE_H
#define _DH_WITH_derive_H

/* TA 的 UUID */
#define TA_DH_WITH_DERIVE_UUID \
    { 0x1ed4f182, 0x7b22, 0x4aaa, \
        { 0x86, 0xba, 0x9d, 0xc0, 0x69, 0xaf, 0x42, 0x76} }

/* 所有的椭圆曲线密钥交换算法类型，普通的DH算法需要的密钥较大，不推荐使用 */
enum dh_algorithm_type {
    DH_ALGORITHM_TYPE_ECDH_P192, /* 基于椭圆曲线的DH算法 */
    DH_ALGORITHM_TYPE_ECDH_P224,
    DH_ALGORITHM_TYPE_ECDH_P256,
    DH_ALGORITHM_TYPE_ECDH_P384,
    DH_ALGORITHM_TYPE_ECDH_P521,
    DH_ALGORITHM_TYPE_X25519,     /* 基于X25519的DH算法 */

    DH_ALGORITHM_TYPE_MAX,
};

/*
 * DH_WITH_DERIVE_CMD_INIT - 初始化密钥交换环境
 * 该命令设置算法类型，并生成本地密钥对
 * param[0] (value) 算法类型枚举 - 参考 enum dh_algorithm_type
 * param[1] (memref) REE侧公钥
 * param[2] (unused)
 * param[3] (unused)
 */
#define DH_WITH_DERIVE_CMD_INIT 0 /* 初始化密钥交换环境 */

/*
 * DH_WITH_DERIVE_CMD_GET_TA_PUBLIC_KEY - 获取TA侧的公钥
 * param[0] (memref) - 存储TA侧公钥的缓冲区
 * param[1] (unused)
 * param[2] (unused) 
 * param[3] (unused)
 */
#define DH_WITH_DERIVE_CMD_GET_TA_PUBLIC_KEY 1 /* 获取TA侧公钥 */

/*
 * DH_WITH_DERIVE_CMD_GET_DERIVE_KEY - 获取TA生成的派生密钥
 * param[0] (memref) - 共享密钥
 * param[1] (unused)
 * param[2] (unused) 
 * param[3] (unused)
 */
#define DH_WITH_DERIVE_CMD_GET_DERIVE_KEY 2 /* 获取TA生成的派生密钥 自己在PC上区验证 */

#endif /* _DH_WITH_DERIVE_H */
