# 介绍

本项目为OP-TEE API的所有使用示例, 大部分案例中不止使用一个算法，而是使用了许多同类的算法，因此有许多额外的不相关的函数解决不同算法所需要的要求
还在逐步更新中...

# 如何快速新建一个OP-TEE空工程
 - 在脚本目录下运行`pyhton3 create_pro.py [project_name]`命令
将会在当前目录下生成一个`project_name`目录，其中包含了和官方案例结构一样的文件.不需要手动设置UUID信息，脚本会自动生成。
可以按需修改栈大小(默认2K)和数据堆大小(默认32K)。人
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

# 本项目所有示例:

## 存储系列
 - [安全存储(secure_storage_01)](secure_storage_01/README.md) : 在REE创建持久化存储对象

## 密码学系列
 - [对称加密(symmetric_cipher)](symmetric_cipher/README.md) : AES加密算法的使用

 - [非对称加密(asymmetric_cipher)](asymmetric_cipher/README.md) : RSA加密算法的使用

 - [签名验签(sign_and_verify)](sign_and_verify/README.md) : RSA/椭圆曲线 签名验签算法的使用

 - [信息摘要(message_digest)](message_digest/README.md) : HASH算法的使用,MD5,SHA256等

 - [消息认证码(h_mac)](h_mac/README.md) : HMAC算法的使用

 - [密钥交换(dh_with_derive)](dh_with_derive/README.md) : 椭圆曲线密钥交换算法的使用

 - [加密认证(aes_gcm_ccm)](aes_gcm_ccm/README.md) : AES-GCM,AES-CCM算法的使用