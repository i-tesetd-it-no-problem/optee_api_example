from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


# DH算法枚举
class dh_algorithm_type:
    DH_ALGORITHM_TYPE_ECDH_P192 = 0
    DH_ALGORITHM_TYPE_ECDH_P224 = 1
    DH_ALGORITHM_TYPE_ECDH_P256 = 2
    DH_ALGORITHM_TYPE_ECDH_P384 = 3
    DH_ALGORITHM_TYPE_ECDH_P521 = 4
    DH_ALGORITHM_TYPE_X25519 = 5


# ========= 用户需要修改的部分 =========

# 第一步：替换下面的数组定义, 由 gen_ecdh_keypair.py 生成的对应算法的私钥
private_key_der = bytes([
    0xF0, 0xFF, 0x7C, 0xE3, 0x07, 0xF5, 0x06, 0xF7, 0x44, 0x5B, 0x28, 0x82, 0x07, 0xC6, 0x05, 0x0D,
    0x3F, 0x54, 0x8B, 0x80, 0x72, 0x1B, 0xA0, 0xD9, 0xB8, 0x62, 0x5F, 0x76, 0xE1, 0x89, 0x7F, 0x6B,
])

# 第二步：替换下面的字符串为从 TA 获取的公钥，即通过 DH_WITH_DERIVE_CMD_GET_TA_PUBLIC_KEY 命令获取到的值
peer_public_key_bytes = bytes.fromhex(
    "b532ae75f762db5ea042e87b1e365d11e619ebb94e41e743363f1a60fc19af14"
)

# 第三步：选择所需的算法类型，根据当前 CA 使用的算法选择正确的算法类型
algorithm_type = dh_algorithm_type.DH_ALGORITHM_TYPE_X25519  # 这里可以根据需要选择不同算法类型

# ========= 用户不需要修改的部分 =========

# 算法类型映射
curve_map = {
    dh_algorithm_type.DH_ALGORITHM_TYPE_ECDH_P192: ec.SECP192R1(),
    dh_algorithm_type.DH_ALGORITHM_TYPE_ECDH_P224: ec.SECP224R1(),
    dh_algorithm_type.DH_ALGORITHM_TYPE_ECDH_P256: ec.SECP256R1(),
    dh_algorithm_type.DH_ALGORITHM_TYPE_ECDH_P384: ec.SECP384R1(),
    dh_algorithm_type.DH_ALGORITHM_TYPE_ECDH_P521: ec.SECP521R1(),
}

# 根据算法类型加载私钥和计算共享密钥
if algorithm_type == dh_algorithm_type.DH_ALGORITHM_TYPE_X25519:
    try:
        # X25519 的私钥处理方式
        private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_der)
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        # 使用X25519的私钥生成共享密钥
        shared_key = private_key.exchange(peer_public_key)
    except ValueError as e:
        print(f"X25519 私钥加载失败: {e}")
        exit(1)
else:
    try:
        # 加载私钥（仅适用于ECDH算法）
        private_key = serialization.load_der_private_key(
            private_key_der,
            password=None,
            backend=default_backend()
        )
    except ValueError as e:
        print(f"私钥加载失败: {e}")
        exit(1)

    # 根据算法类型获取对应的椭圆曲线类
    try:
        curve = curve_map[algorithm_type]
    except KeyError:
        print(f"不支持的算法类型: {algorithm_type}")
        exit(1)

    try:
        # 生成对端公钥
        peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            curve,
            peer_public_key_bytes
        )
    except ValueError as e:
        print(f"对端公钥加载失败: {e}")
        exit(1)

    try:
        # 使用ECDH的私钥生成共享密钥
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    except Exception as e:
        print(f"共享密钥生成失败: {e}")
        exit(1)

# 打印共享密钥
print(f"共享密钥: {shared_key.hex()}")
print(f"共享密钥长度: {len(shared_key)} 字节")
