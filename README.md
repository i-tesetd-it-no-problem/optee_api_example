# 目录
- [介绍](#介绍)
- [如何使用 `create_pro.py` 快速新建一个OP-TEE空工程](#如何使用-create_propy-快速新建一个op-tee空工程)
- [注意](#注意)
- [OpenSSL介绍](#openssl介绍)
- [密码学系列](#密码学系列)
- [一些CA的API](#一些ca的api)
- [时间系列](#时间系列)
- [安全存储](#安全存储)
- [随机数](#随机数)
# 介绍

本项目为OP-TEE API的所有使用示例, 大部分案例中不止使用一个算法，而是使用了许多同类的算法，因此有许多额外的不相关的函数解决不同算法所需要的要求
还在逐步更新中...

# 如何使用 `create_pro.py` 快速新建一个OP-TEE空工程
 - 如果使用开发板验证CA/TA，由于每次新建项目都要使用不同的传输命令，为了节省时间, 本脚本会在CA/TA文件末尾自动生成一条指令。使用SSH命令传输CA/TA到开发板，请提前修改`create_pro.py`文件中的`DEFAULT_HOST_NAME`与`DEFAULT_IP`变量
 - 效果如下:
 ```c
 /**
 * @brief 配置到开发板指令

 * 注意: 开发本需提前配置好SSH环境, 
 * 根文件系统也需要支持OPTEE, buildroot自行配置

 * /lib/optee_armtz 是OPTEE寻找TA的默认地址
 * /usr/bin 让CA目标文件可以直接当作命令运行

 * scp test/ta/71e29ed5-08cb-4df8-b4ba-28789c93614a.ta root@127.0.0.1/lib/optee_armtz
 * scp test/host/test root@127.0.0.1/usr/bin
 */

 ```
 - 在脚本目录下运行`pyhton3 create_pro.py [project_name]`命令
将会在当前目录下生成一个`project_name`目录，其中包含了和官方案例结构一样的文件.不需要手动设置UUID信息，脚本会自动生成。
可以按需修改栈大小(默认2K)和数据堆大小(默认32K).
 - 生成的工程可直接编译，本质是一个毫无作用的空工程
 - 自行导入本地交叉编译工具链之后，运行`make -C [project_name]`即可编译生成CA/TA文件，CA可执行文件默认为脚本输入参数`project_name`
 - 以新建`test`项目为例

```shell
python3 create_pro.py test
```

生成的目录结构和官方的案例结构一模一样,如下：
```
├── host
│   ├── main.c
│   └── Makefile
├── Makefile
└── ta
    ├── include
    │   └── test.h
    ├── Makefile
    ├── sub.mk
    ├── test.c
    └── user_ta_header_defines.h
```

- 编译后的目录结构如下：

```
├── host
│   ├── main.c
│   ├── main.o
│   ├── Makefile
│   └── test
├── Makefile
└── ta
    ├── 7149fcc8-cdeb-407a-a70d-85d2bda55b51.dmp
    ├── 7149fcc8-cdeb-407a-a70d-85d2bda55b51.elf
    ├── 7149fcc8-cdeb-407a-a70d-85d2bda55b51.map
    ├── 7149fcc8-cdeb-407a-a70d-85d2bda55b51.stripped.elf
    ├── 7149fcc8-cdeb-407a-a70d-85d2bda55b51.ta
    ├── dyn_list
    ├── include
    │   └── test.h
    ├── Makefile
    ├── sub.mk
    ├── ta_entry_a32.o
    ├── ta.lds
    ├── test.c
    ├── test.o
    ├── user_ta_header_defines.h
    └── user_ta_header.o
```

## 注意:
如要验证某个算法案例，请先将对应的工程移到根目录下，然后再运行`make -C [project_name]`
可以使用如下命令生成clangd配置文件
```shell
pip install compiledb # 先安装compiledb
compiledb -n make -C [project_name] # 生成clangd配置文件compile_commands.json
```

## OpenSSL介绍
 - [OpenSSL介绍](openssl/README.md)

## 密码学系列
 - [AES-ECB-NOPAD](Cryptography/aes_ecb_nopad)
 - [AES-CBC-NOPAD](Cryptography/aes_cbc_nopad)
 - [AES-CTR](Cryptography/aes_ctr)
 - [AES-CTS](Cryptography/aes_cts)
 - [AES-XTS](Cryptography/aes_xts)
 - [AES-CBC-MAC-NOPAD](Cryptography/aes_cbc_mac_nopad)
 - [AES-CBC-MAC-PKCS5](Cryptography/aes_cbc_mac_pkcs5)
 - [AES-CMAC](Cryptography/aes_cmac)
 - [AES-CCM](Cryptography/aes_ccm)
 - [AES-GCM](Cryptography/aes_gcm)
 - [SM4-ECB-NOPAD](Cryptography/sm4_ecb_nopad)
 - [SM4-CBC-NOPAD](Cryptography/sm4_cbc_nopad)
 - [SM4-CTR](Cryptography/sm4_ctr)
 - [RSASSA-PKCS1-V1_5系列](Cryptography/rsassa_pkcs1_v1_5_xxx)
 - [RSASSA-PKCS1-PSS-MGF1系列](Cryptography/rsassa_pkcs1_pss_mgf1_xxx)
 - [RSAES-PKCS1-V1_5系列](Cryptography/rsaes_pkcs1_v1_5)
 - [RSAES-PKCS1-OAEP-MGF1系列](Cryptography/rsaes_pkcs1_oaep_mgf1_xxx)
 - [DH-DERIVE-SHARED-SECRET](Cryptography/dh_basic)
 - [HASH系列](Cryptography/hash)
 - [HMAC系列](Cryptography/hmac_xxx)
 - [ECDSA系列](Cryptography/ecdsa_xxx)
 - [ED25519](Cryptography/ed25519)
 - [ECDH系列](Cryptography/ecdh_xxx)
 - [ECDH-X25519](Cryptography/ecdh_x25519)

### 推荐(以安全性与效率为参考)
 - `对称加密[认证加密]算法`推荐使用 [AES-GCM](Cryptography/aes_gcm)
 - `对称加密[认证加密]算法`推荐使用 [AES-CCM](Cryptography/aes_ccm)
 - `非对称加密算法`推荐使用 [RSAES-PKCS1-OAEP-MGF1系列](Cryptography/rsaes_pkcs1_oaep_mgf1_xxx)
 - `签名算法`推荐使用 1 : RSA签名 : [RSASSA-PKCS1-PSS-MGF1系列](Cryptography/rsassa_pkcs1_pss_mgf1_xxx)
 - `签名算法`推荐使用 2 : 椭圆曲线签名 : [ED25519](Cryptography/ed25519)
 - `摘要算法`推荐使用 [HASH系列](Cryptography/hash)
 - `消息认证算法`推荐使用 [HMAC系列](Cryptography/hmac_xxx)
 - `密钥交换算法`推荐使用 [ECDH-X25519](Cryptography/ecdh_x25519)
 - 上述某些算法中如果关系到`HASH`算法，则使用的`HASH`摘要长度越长安全性越高，但同时也会增加计算花费时间。自行抉择

## 一些CA/TA的API
 - [申请/注册共享内存](client_api/shared_mem)
    - `TEEC_AllocateSharedMemory` : 申请共享内存
    - `TEEC_RegisterSharedMemory` : 注册共享内存
    - `TEEC_ReleaseSharedMemory`  : 释放共享内存
 - [取消TA调用](client_api/cancel)
    - `TEEC_RequestCancellation`  : CA发起请求取消 OpenSession 或 Invok 调用
    - `TEE_UnmaskCancellation`    : 解除屏蔽取消标志, 即, 使TA允许被取消
    - `TEE_MaskCancellation`      : 屏蔽取消标志, 即, 不允许TA被取消(默认)
    - `TEE_GetCancellationFlag`   : 获取当前取消屏蔽标志

## 时间系列
 - [安全时间](test_time)

## 安全存储
 - [安全存储](secure_storage)

## 随机数
 - [随机数](rng)