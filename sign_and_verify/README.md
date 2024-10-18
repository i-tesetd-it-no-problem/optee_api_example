# 签名与验签示例

## 介绍

本示例展示了如何使用 OP-TEE 提供的 API 进行签名和验签。

## 流程
- TA生成一对密钥对，使用私钥对数据进行签名，公钥对数据进行验签。
    - `TEE_AllocateTransientObject` 根据算法类型申请瞬态对象
    - `TEE_InitValueAttribute` 某些算法需要初始化属性
    - `TEE_GenerateKey` 生成密钥对
- 对原始数据进行摘要计算
    - `TEE_AllocateOperation` 申请摘要操作句柄
    - `TEE_DigestDoFinal`一次性计算摘要
- 使用私钥对摘要进行签名
    - `TEE_AsymmetricSignDigest` 签名
- 使用公钥对签名进行验签
    - `TEE_AsymmetricVerifyDigest` 验签

## 注意

`ED25519`算法不需要主动进行摘要计算，在生成签名时会自己进行摘要