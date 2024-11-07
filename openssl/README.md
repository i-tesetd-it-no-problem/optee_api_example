# OpenSSL 命令行工具概览

- [介绍](#介绍)
- [常见的密钥和证书格式](#常见的密钥和证书格式)
    - [1. PEM（Privacy Enhanced Mail）](#1-pemprivacy-enhanced-mail)
    - [2. DER（Distinguished Encoding Rules）](#2-derdistinguished-encoding-rules)
- [命令使用介绍](#命令使用介绍)
- [案例](#案例)

## 介绍
OpenSSL 是一套开源的密码学软件库，可以用来安全地进行加密、数字签名、证书管理等操作。它包括了 SSL/TLS、X.509 证书等各种功能。

## 常见的密钥和证书格式

### 1. PEM（Privacy Enhanced Mail）
- **编码方式**：使用 Base64 编码，并在文件头尾添加标识（例如 `-----BEGIN CERTIFICATE-----` 和 `-----END CERTIFICATE-----`）。
- **文件扩展名**：通常为 `.pem`、`.crt`、`.cer` 或 `.key`，根据内容不同有所变化。
- **内容类型**：可用于存储证书、私钥、公钥等，支持多种内容。
- **用途**：适用于文本传输（如电子邮件、HTTP 等），易于复制、粘贴，通常用于 OpenSSL 生成和解析的文件。
- **示例**：
  ```
  -----BEGIN CERTIFICATE-----
  MIIC+zCCAeOgAwIBAgIJAK8q3ieaxMefMA0GCSqGSIb3DQEBCwUAMBgxFjAUBgNV
  BAMMDXNvbWUuZXhhbXBsZS5jb20wHhcNMjMwNTEyMTIxNDQ2WhcNMjQwNTEyMTIx
  ...
  -----END CERTIFICATE-----
  ```

### 2. DER（Distinguished Encoding Rules）
- **编码方式**：使用二进制编码。
- **文件扩展名**：常为 `.der` 或 `.cer`。
- **内容类型**：通常用于存储证书、私钥、公钥。
- **用途**：适合于纯二进制传输和存储，广泛用于 Java 等需要二进制格式的系统。
- **示例**：DER 文件无法直接用文本编辑器查看，因为它是二进制格式。

| 特性          | PEM           | DER           |
| ------------- | ------------- | ------------- |
| 编码方式      | Base64 编码   | 二进制编码    |
| 文件扩展名    | `.pem`、`.crt`、`.cer`、`.key` | `.der`、`.cer` |
| 用途          | 文本传输和拷贝 | 二进制传输和存储 |
| 内容支持      | 证书、私钥、公钥 | 证书、私钥、公钥 |

## 命令使用介绍

OpenSSL 提供了强大的命令行工具，支持多种密码学操作，用于管理密钥、证书、消息摘要等。
### 1. 公钥与私钥管理相关

- **genpkey**：生成公私钥对，支持多种算法（如 RSA、DSA、EC）。
- **pkey**：用于公私钥管理，包括查看、转换私钥格式等。
- **pkeyutl**：执行基于公钥的加密、解密、签名和验证操作。
- **ecparam**：生成和处理椭圆曲线参数。

### 2. 证书管理与生成

- **req**：生成证书签名请求（CSR），可以生成自签名证书或请求 CA 签名。
- **x509**：管理 X.509 证书，包括查看、转换和自签名等操作。
- **ca**：用作证书颁发机构（CA）生成和管理证书。
- **ts**：处理时间戳请求和响应。

### 3. 加密与解密相关

- **enc**：用于对文件或数据块进行加密和解密，支持多种加密算法。
- **rsautl**：使用 RSA 进行低级别加密和解密操作（逐渐被弃用，推荐使用 `pkeyutl`）。

### 4. 消息摘要与校验

- **dgst**：生成和验证消息摘要（哈希），支持常见哈希算法如 MD5、SHA-256 等。
- **asn1parse**：用于查看 ASN.1 格式数据的结构。

### 5. Diffie-Hellman 相关

- **dhparam**：生成 Diffie-Hellman 参数，用于密钥交换。

### 6. 椭圆曲线相关

- **ec**：用于管理和处理椭圆曲线密钥，支持查看和导出密钥。

### 7. 随机数生成

- **rand**：生成随机数，可以指定生成的数据字节数，用于密码学应用。

### 8. 测试与调试工具

- **speed**：测试各种加密算法的性能，测量其速度和效率。
- **verify**：验证 X.509 证书的有效性。

### 9. PKCS 相关

- **pkcs12**：管理 PKCS#12 格式的文件（例如 .p12 文件，包含证书和私钥）。
- **pkcs7**：处理 PKCS#7 格式的数据，用于签名和加密消息的处理。

### 10. S/MIME 与其他应用

- **smime**：处理 S/MIME 格式的数据，主要用于电子邮件的加密和签名操作。

## 案例
- [HSAH](HSAH/HSAH.md)
- [AES](AES/AES.md)
- [RSA](RSA/RSA.md)
- [ECDSA](ECDSA/ECDSA.md)
- [ECDH](ECDH/ECDH.md)