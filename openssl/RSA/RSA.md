# OpenSSL RSA 命令使用指南

## 介绍

**RSA** 是一种广泛使用的非对称加密算法，用于确保数据的保密性和完整性。它基于两个大质数的乘积实现密钥生成，具有公钥和私钥两部分。典型的应用场景包括：

- **加密与解密**：公钥加密数据，私钥进行解密，用于保护敏感信息的安全传输。
- **数字签名**：私钥对数据进行签名，公钥用于验证签名，以确保数据的完整性和来源。

## 目录

- [1. 生成 RSA 密钥对](#1-生成-rsa-密钥对)
  - [1.1 生成私钥](#11-生成私钥)
  - [1.2 使用密码加密私钥](#12-使用密码加密私钥)
  - [1.3 解密加密的私钥](#13-解密加密的私钥)
  - [1.4 提取公钥](#14-提取公钥)
- [2. 格式转换](#2-格式转换)
  - [2.1 PEM 到 DER](#21-pem-到-der)
  - [2.2 DER 到 PEM](#22-der-到-pem)
- [3. 加密和解密](#3-加密和解密)
  - [3.1 公钥加密和私钥解密](#31-公钥加密和私钥解密)
- [4. 签名和验签](#4-签名和验签)
  - [4.1 使用私钥签名](#41-使用私钥签名)
  - [4.2 使用公钥验签](#42-使用公钥验签)
- [5. 查看和验证密钥信息](#5-查看和验证密钥信息)
  - [5.1 查看私钥信息](#51-查看私钥信息)
  - [5.2 查看公钥信息](#52-查看公钥信息)
- [6. 常用选项说明](#6-常用选项说明)
- [7. 完整加/解密流程](#7-完整加解密流程)
- [8. 完整签名/验签流程](#8-完整签名验签流程)

## 1. 生成 RSA 密钥对

### 1.1 生成私钥

生成 2048 位 RSA 私钥：

```sh
openssl genrsa -out priv_key.pem 2048
```

- 默认生成的私钥文件是 PEM 格式。
- 生成更高位数的密钥，例如 4096 位，可以将 `2048` 替换为 `4096`。

### 1.2 使用密码加密私钥

生成私钥时添加密码保护：

```sh
openssl genrsa -aes256 -out encrypted_priv_key.pem 2048
```

- 使用 `-aes256` 或其他加密算法对私钥进行加密。

或者对现有私钥进行加密：

```sh
openssl rsa -in priv_key.pem -aes256 -out encrypted_priv_key.pem
```

### 1.3 解密加密的私钥

将加密的私钥转换为未加密的形式：

```sh
openssl rsa -in encrypted_priv_key.pem -out decrypted_priv_key.pem
```

- 需要输入加密时设置的密码。

### 1.4 提取公钥

从私钥中提取公钥：

```sh
openssl rsa -in priv_key.pem -pubout -out pub_key.pem
```

- 使用 `-pubout` 参数生成公钥文件。

## 2. 格式转换

### 2.1 PEM 到 DER

将 PEM 格式的密钥文件转换为 DER 编码格式：

```sh
openssl rsa -in priv_key.pem -outform der -out priv_key.der
openssl rsa -in pub_key.pem -pubin -outform der -out pub_key.der
```

### 2.2 DER 到 PEM

将 DER 格式的密钥文件转换回 PEM 格式：

```sh
openssl rsa -in priv_key.der -inform der -out priv_key.pem
openssl rsa -in pub_key.der -inform der -pubin -out pub_key.pem
```

## 3. 加密和解密

### 3.1 公钥加密和私钥解密

#### 3.1.1 使用公钥加密数据

使用公钥对数据进行加密：

```sh
openssl pkeyutl -encrypt -inkey pub_key.pem -pubin -in plaintext.txt -out encrypted.bin
```

- 使用 `-encrypt` 参数指定加密操作。
- `-inkey pub_key.pem` 指定用于加密的公钥。

#### 3.1.2 使用私钥解密数据

使用私钥对加密的数据进行解密：

```sh
openssl pkeyutl -decrypt -inkey priv_key.pem -in encrypted.bin -out decrypted.txt
```

- 使用 `-decrypt` 参数指定解密操作。
- `-inkey priv_key.pem` 指定用于解密的私钥。

## 4. 签名和验签

### 4.1 使用私钥签名

使用私钥对数据进行签名：

```sh
openssl dgst -sha256 -sign priv_key.pem -out signature.bin plaintext.txt
```

- 使用 `-sha256` 对数据进行摘要处理。
- `-sign` 参数表示使用私钥进行签名。

### 4.2 使用公钥验签

使用公钥验证签名：

```sh
openssl dgst -sha256 -verify pub_key.pem -signature signature.bin plaintext.txt
```

- `-verify` 参数表示使用公钥进行签名验证。

## 5. 查看和验证密钥信息

### 5.1 查看私钥信息

查看私钥的详细信息：

```sh
openssl rsa -in priv_key.pem -text -noout
```

- `-text`：以文本形式打印私钥内容。
- `-noout`：不输出密钥本身，只显示信息。

### 5.2 查看公钥信息

查看公钥的信息：

```sh
openssl rsa -in pub_key.pem -pubin -text -noout
```

- `-pubin`：表示输入是公钥文件。

## 6. 常用选项说明

- `-in filename`：指定输入文件名。
- `-out filename`：指定输出文件名。
- `-outform PEM|DER`：指定输出文件格式，可以是 PEM 或 DER。
- `-inform PEM|DER`：指定输入文件格式。
- `-pubout`：表示输出公钥。
- `-pubin`：表示输入是公钥。
- `-aes256`、`-des3`：指定加密算法对密钥进行加密。
- `-text`：以可读文本形式打印密钥内容。
- `-noout`：只打印密钥信息，不打印密钥内容。
- `-encrypt`：使用公钥加密数据。
- `-decrypt`：使用私钥解密数据。
- `-sign`：使用私钥对数据进行签名。
- `-verify`：使用公钥验证签名。

## 7. 完整加/解密流程

```sh
# 生成私钥（2048位），使用 AES-256 加密保护，请妥善保管密码
openssl genrsa -aes256 -out priv_key.pem 2048

# 提取公钥
openssl rsa -in priv_key.pem -pubout -out pub_key.pem

# 公钥加密
openssl pkeyutl -encrypt -inkey pub_key.pem -pubin -in plaintext.txt -out encrypted.bin

# 私钥解密
openssl pkeyutl -decrypt -inkey priv_key.pem -in encrypted.bin -out decrypted.txt
```

## 8. 完整签名/验签流程

```sh
# 生成私钥（2048位），使用 AES-256 加密保护，请妥善保管密码
openssl genrsa -aes256 -out priv_key.pem 2048

# 提取公钥
openssl rsa -in priv_key.pem -pubout -out pub_key.pem

# 使用私钥对摘要数据签名
openssl dgst -sha256 -sign priv_key.pem -out signature.bin plaintext.txt

# 使用公钥验证签名
openssl dgst -sha256 -verify pub_key.pem -signature signature.bin plaintext.txt
```

