# OpenSSL 椭圆曲线 (ECC) 认证指南

## 介绍

椭圆曲线密码学 (ECC) 是一种基于椭圆曲线数学结构的公钥加密技术。它以较短的密钥长度提供与传统 RSA 加密相当的安全性，同时具有更高的计算效率，因此被广泛应用于现代加密协议，如 TLS 和区块链技术。本指南将介绍如何使用 OpenSSL 工具进行 ECC 密钥对的生成、签名和验签。

## 目录

1. [生成 ECC 密钥对](#1-生成-ecc-密钥对)  
   1.1 [生成 ECC 私钥](#11-生成-ecc-私钥)  
   1.2 [提取 ECC 公钥](#12-提取-ecc-公钥)  
2. [使用 ECC 进行签名和验签](#2-使用-ecc-进行签名和验签)  
   2.1 [使用 ECC 私钥签名](#21-使用-ecc-私钥签名)  
   2.2 [使用 ECC 公钥验证签名](#22-使用-ecc-公钥验证签名)  
3. [完整签名和验签流程示例](#3-完整签名和验签流程示例)  

## 1. 生成 ECC 密钥对

### 1.1 生成 ECC 私钥
首先，使用 P-521（又称 `secp521r1`）椭圆曲线来生成 ECC 私钥，命令如下：

```sh
openssl ecparam -name secp521r1 -genkey -noout -out ec_priv_key.pem
```

**解释**：
- `openssl ecparam`：用于生成 EC 参数或密钥。
- `-name secp521r1`：指定要使用的椭圆曲线名称。
- `-genkey`：生成 EC 私钥。
- `-noout`：不输出 EC 参数，只输出密钥。
- `-out ec_priv_key.pem`：将生成的私钥保存到 `ec_priv_key.pem` 文件中。

### 1.2 提取 ECC 公钥
接下来，从生成的私钥中提取公钥，以便用于签名验证：

```sh
openssl ec -in ec_priv_key.pem -pubout -out ec_pub_key.pem
```

**解释**：
- `openssl ec`：用于处理 EC 密钥。
- `-in ec_priv_key.pem`：指定输入的 EC 私钥文件。
- `-pubout`：输出公钥部分。
- `-out ec_pub_key.pem`：将公钥保存到 `ec_pub_key.pem` 文件中。

## 2. 使用 ECC 进行签名和验签

### 2.1 使用 ECC 私钥签名
接下来使用私钥对数据进行签名。假设有一个数据文件 `plaintext.txt`，使用以下命令对其进行签名：

```sh
openssl dgst -sha256 -sign ec_priv_key.pem -out ec_signature.bin plaintext.txt
```

**解释**：
- `openssl dgst`：用于计算和签名消息摘要。
- `-sha256`：指定使用 SHA-256 哈希算法。
- `-sign ec_priv_key.pem`：使用指定的私钥文件进行签名。
- `-out ec_signature.bin`：将生成的签名保存到 `ec_signature.bin` 文件中。
- `plaintext.txt`：要签名的原始数据文件。

### 2.2 使用 ECC 公钥验证签名
使用公钥验证签名的正确性，确保数据的完整性和签名的有效性：

```sh
openssl dgst -sha256 -verify ec_pub_key.pem -signature ec_signature.bin plaintext.txt
```

**解释**：
- `-verify ec_pub_key.pem`：使用指定的公钥文件进行验证。
- `-signature ec_signature.bin`：指定要验证的签名文件。
- 其他选项同上。

如果签名验证通过，命令会输出：

```sh
Verified OK
```

如果验证失败，则会输出：

```sh
Verification Failure
```

## 3. 完整签名和验签流程示例

```sh
# 生成 ECC 私钥
openssl ecparam -name secp521r1 -genkey -noout -out ec_priv_key.pem

# 提取 ECC 公钥
openssl ec -in ec_priv_key.pem -pubout -out ec_pub_key.pem

# 对数据文件进行签名
openssl dgst -sha256 -sign ec_priv_key.pem -out ec_signature.bin plaintext.txt

# 验证签名的有效性
openssl dgst -sha256 -verify ec_pub_key.pem -signature ec_signature.bin plaintext.txt
```

