# OpenSSL HASH 使用指南

## 目录

1. [介绍](#介绍)
2. [生成 HASH 值](#生成-hash-值)
   - [MD5 生成](#md5-生成)
   - [SHA256 生成](#sha256-生成)
   - [SHA512 生成](#sha512-生成)
   - [SHA1 生成](#sha1-生成)
3. [验证 HASH 值](#验证-hash-值)
   - [与预期 HASH 值比较](#与预期-hash-值比较)
4. [其他常用 HASH 算法](#其他常用-hash-算法)
5. [HASH 值输出](#hash-值输出)
   - [查看 HASH 值](#查看-hash-值)
   - [输出到文件](#输出到文件)
6. [示例流程](#示例流程)

## 介绍

HASH（散列）函数是一种将任意大小的数据转换为固定大小散列值的算法，用于数据完整性检查。常见的散列算法有 MD5、SHA1、SHA256、SHA512 等。本文介绍如何使用 OpenSSL 生成和验证 HASH 值，以确保数据在传输或存储过程中未被篡改。

## 1. 生成 HASH 值

### 1.1 MD5 生成

```sh
openssl dgst -md5 -out hash.md5 plaintext.txt
```
- **注意**：MD5 存在已知安全漏洞，不推荐使用。

### 1.2 SHA256 生成

```sh
openssl dgst -sha256 -out hash.sha256 plaintext.txt
```
- `SHA256` 适用于大部分场景，安全性较高。

### 1.3 SHA512 生成

```sh
openssl dgst -sha512 -out hash.sha512 plaintext.txt
```
- `SHA512` 提供更高安全性，适用于需要更高安全保障的场景。

### 1.4 SHA1 生成

```sh
openssl dgst -sha1 -out hash.sha1 plaintext.txt
```
- **注意**：SHA1 不再安全，建议避免使用。

## 2. 验证 HASH 值

### 2.1 与预期 HASH 值比较

```sh
openssl dgst -sha256 plaintext.txt
```
- 输出当前文件的 HASH 值，与存储的 `hash.sha256` 进行手动比对。

## 3. 其他常用 HASH 算法

- **MD5**：`-md5`，不推荐。
- **SHA1**：`-sha1`，已过时。
- **SHA256**：`-sha256`，常用。
- **SHA512**：`-sha512`，更高安全性。

## 4. HASH 值输出

### 4.1 查看 HASH 值

```sh
openssl dgst -sha256 plaintext.txt
```
- 直接在控制台输出。

### 4.2 输出到文件

```sh
openssl dgst -sha256 -out hash.sha256 plaintext.txt
```
- 保存 HASH 值到文件。

## 5. 示例流程

### 5.1 生成并验证 HASH 值

```sh
# 生成哈希值
openssl dgst -sha256 -out hash.sha256 plaintext.txt

# 查看哈希值
openssl dgst -sha256 plaintext.txt
```
- 手动比对文件和输出结果。
