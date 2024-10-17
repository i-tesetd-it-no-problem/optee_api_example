# 密钥交换算法案例

## 额外文件介绍
 - gen_dh_keypair.py : 生成本案例所有算法需要使用的密钥对
 - validate_derive_key.py : 用于验证双方密钥交换算法派生密钥是否相同
 - dh_keys.c/h : 由gen_dh_keypair.py生成的密钥对头文件与源文件

## 编译备工作
 - 使用`python3 gen_dh_keypair.py`生成头文件与源文件
    - 此脚本只会为不同的算法生成一对密钥对用于CA的密钥交换, TA会自己生成一对密钥对用于密钥交换
 - 生成dh_keys.c/h文件之后才可以编译

## 本案例的工作流程
 - TA派生密钥
    - CA首先将选择的算法，以及脚本自动生成的算法对应的密钥对的公钥发送给TA
    - TA自己在TEE侧根据传入的算法使用`TEE_GenerateKey`接口生成一对密钥对
    - TA使用自己生成的私钥与传入的CA的公钥，使用`TEE_DeriveKey`接口派生出用于加密的对称密钥
 - CA获取TA上一步自己生成的密钥对的公钥
 - CA获取TA派生出的对称密钥
    - 这一步不符合实际使用使用场景，派生密钥不应该传输,这里只是为了后续验证双方派生的密钥是否相同
 - 验证过程需要自己手动操作, 修改`validate_derive_key.py`脚本，参考其中的修改步骤
    - 1. 替换`private_key_der`变量为`gen_dh_keypair.py`生成的`dh_key.c`文件中对应算法的私钥
    - 2. 替换`peer_public_key_bytes`变量为第二步获取到的TA生成的密钥对的公钥
    - 3. 修改变量algorithm_type为对应使用的算法类型
    - 4. 运行脚本,使用`python3 validate_derive_key.py`命令运行脚本,脚本会根据TA的公钥与CA的公钥派生出对称密钥，自行比对对称密钥与第三步获取到的TA派生出的对称密钥是否相同

## 注：
CA/TA代码中已经给出了详细的注释