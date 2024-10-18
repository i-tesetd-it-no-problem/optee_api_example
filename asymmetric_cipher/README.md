# 非对称加密算法案例

## 步骤一：生成密钥对
 - `TEE_AllocateTransientObject` 申请瞬态对象，用于存放密钥对 使用`TEE_TYPE_RSA_KEYPAIR`类型
 - `TEE_GenerateKey` 生成密钥对

## 步骤二：加密数据
 - `TEE_AllocateOperation` 申请操作句柄 选择对应算法 `TEE_MODE_ENCRYPT`模式
 - `TEE_SetOperationKey` 设置操作句柄的密钥
 - `TEE_AsymmetricEncrypt` 加密数据

## 步骤三：解密数据
 - `TEE_AllocateOperation` 申请操作句柄 选择对应算法 `TEE_MODE_DECRYPT`模式
 - `TEE_SetOperationKey` 设置操作句柄的密钥
 - `TEE_AsymmetricDecrypt` 解密数据

## 完整代码