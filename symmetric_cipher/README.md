# AES对称密钥案例

## 介绍

本案例展示了如何使用TEE内核提供的AES对称加密算法。实现了AES加密和解密功能。

## 步骤一 生成密钥
    - `TEE_AllocateTransientObject` 选择 `TEE_TYPE_AES_KEY` 类型，生成一个AES密钥对象。
    - `TEE_GenerateKey` 使用随机数生成器生成一个AES密钥。
    - 使用`TEE_GenerateRandom`生成随机数，作为IV（初始向量）。

## 步骤二 加密数据
    - `TEE_AllocateOperation` 选择一个算法，使用`TEE_MODE_ENCRYPT`模式申请操作句柄。
    - `TEE_SetOperationKey` 或 `TEE_SetOperationKey2`设置密钥对象到操作句柄。
    - `TEE_CipherInit` 使用步骤一的和IV，初始化AES加密算法。
    - `TEE_CipherDoFinal` 完成加密，得到加密结果。

## 步骤三 解密数据
    - `TEE_AllocateOperation` 选择一个算法，使用`TEE_MODE_DECRYPT`模式申请操作句柄。
    - `TEE_SetOperationKey` 或 `TEE_SetOperationKey2`设置密钥对象到操作句柄。
    - `TEE_CipherInit` 使用步骤一的和IV，初始化AES解密算法。
    - `TEE_CipherDoFinal` 完成解密，得到解密结果。