import sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# 选择椭圆曲线
# CURVE_NAME = 'secp192r1'
# CURVE_NAME = 'secp224r1'
CURVE_NAME = 'secp256r1'
# CURVE_NAME = 'secp384r1'
# CURVE_NAME = 'secp521r1'


class FixedECDHKeyAESCTR:
    def __init__(self, curve_name='secp256r1'):
        """
        初始化ECDH参数和生成密钥对。
        """
        # 验证曲线名称并选择对应的椭圆曲线
        supported_curves = {
            'secp192r1': ec.SECP192R1(),
            'secp224r1': ec.SECP224R1(),
            'secp256r1': ec.SECP256R1(),
            'secp384r1': ec.SECP384R1(),
            'secp521r1': ec.SECP521R1()
        }

        if curve_name not in supported_curves:
            print(f"Unsupported curve: {curve_name}. Supported curves are: {', '.join(supported_curves.keys())}")
            sys.exit(1)

        self.curve = supported_curves[curve_name]
        # 生成私钥
        self.private_key = ec.generate_private_key(self.curve, default_backend())
        # 获取公钥
        self.public_key = self.private_key.public_key()

    def encrypt(self, key: bytes, plaintext: bytes) -> bytes:
        """
        使用派生的密钥进行AES-CTR加密。
        固定IV为16字节的0x5A。
        """
        iv = b'\x5A' * 16
        cipher = Cipher(
            algorithms.AES(key),
            modes.CTR(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext

    def derive_key(self, peer_public_key_hex: str) -> bytes:
        """
        根据对方的公钥派生共享密钥。
        """
        try:
            # 将十六进制字符串转换为字节
            peer_public_bytes = bytes.fromhex(peer_public_key_hex)
            # 载入对方的公钥
            peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(self.curve, peer_public_bytes)
            # 计算共享秘密
            shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)
            # 使用SHA-256哈希共享秘密，生成AES密钥
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(shared_secret)
            derived_key = digest.finalize()
            return derived_key
        except Exception as e:
            print(f"Error deriving key: {e}")
            sys.exit(1)

    def get_public_key_hex(self) -> str:
        """
        获取本地公钥的十六进制表示（未压缩格式，以'04'开头）。
        """
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        return public_bytes.hex()


def hex_string_to_bytes(hex_str: str, byte_array: bytearray, byte_array_len: int):
    """
    将十六进制字符串转换为字节数组。
    """
    if len(hex_str) != byte_array_len * 2:
        print("Hex string length does not match expected byte array length.")
        sys.exit(1)
    try:
        for i in range(byte_array_len):
            byte_array[i] = int(hex_str[2 * i:2 * i + 2], 16)
    except ValueError:
        print("Invalid hex string.")
        sys.exit(1)


def generate_keypair(crypto: FixedECDHKeyAESCTR):
    """
    生成本地密钥对，并打印公钥的十六进制表示。
    """
    public_key_hex = crypto.get_public_key_hex()
    print(f"{CURVE_NAME} 公钥 (Hex):")
    print(public_key_hex)
    print("\n请将此公钥提供给对方（Alice/Bob）。")


def generate_shared_key(crypto: FixedECDHKeyAESCTR):
    """
    输入对方的公钥，派生共享密钥。
    """
    peer_public_key_hex = input("\n请输入对方的公钥 (Hex):\n").strip()

    # 验证输入的公钥长度
    expected_lengths = {
        'secp192r1': 2 * (1 + 2 * (192 // 8)),
        'secp224r1': 2 * (1 + 2 * (224 // 8)),
        'secp256r1': 2 * (1 + 2 * (256 // 8)),
        'secp384r1': 2 * (1 + 2 * (384 // 8)),
        'secp521r1': 2 * (1 + 2 * (521 // 8 + 1))  # 521 bits需要66字节（132 hex chars）
    }

    expected_length = expected_lengths.get(CURVE_NAME, None)
    if expected_length is None:
        print("Unsupported curve for length validation.")
        sys.exit(1)

    if len(peer_public_key_hex) != expected_length:
        print(f"Invalid public key length for {CURVE_NAME}. Expected {expected_length} hex characters.")
        sys.exit(1)

    # 验证公钥是否以'04'开头
    if not peer_public_key_hex.startswith('04'):
        print("Invalid public key format. Must start with '04'.")
        sys.exit(1)

    # 派生共享密钥
    derived_key = crypto.derive_key(peer_public_key_hex)
    print("派生的密钥:", derived_key.hex())

    # 使用派生的密钥加密消息
    plaintext = b"hello world\n"
    ciphertext = crypto.encrypt(derived_key, plaintext)
    print("密文 (Hex):", ciphertext.hex())
    print("\n请将此密文提供给对方进行解密。")


def main():
    # 初始化ECDH加密类
    crypto = FixedECDHKeyAESCTR(curve_name=CURVE_NAME)

    # 生成密钥对并打印公钥
    generate_keypair(crypto)

    # 派生共享密钥
    generate_shared_key(crypto)


if __name__ == '__main__':
    main()
