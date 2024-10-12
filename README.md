# optee_api_example
OP-TEE的所有案例

# create_pro.py
用于新建一个OP-TEE工程的通用模板的脚本。

## 使用方式
 - 在脚本目录下运行`pyhton3 create_pro.py [project_name]`命令
将会在当前目录下生成一个`project_name`目录，其中包含了和官方案例结构一样的文件.不需要手动设置UUID信息，脚本会自动生成。
可以按需修改栈大小(默认2K)和数据堆大小(默认32K)。
 - 生成的工程可直接编译，本质是一个毫无作用的空工程
 - 自行导入本地交叉编译工具链之后，运行`make -C [project_name]`即可编译生成CA/TA文件，CA可执行文件默认为脚本输入参数`project_name`
 - 以`python3 create_pro.py test`案例为例，生成的目录结构如下：
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