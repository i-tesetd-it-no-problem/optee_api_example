from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import sys


class FixedDHKeyAESCTR:
    def __init__(self, p=None, g=None):
        """
        初始化DH参数和生成密钥对。
        如果提供了p和g，则使用这些参数；否则，生成新的参数。
        """
        if p is None and g is None:
            # 生成1024位的DH参数
            parameters = dh.generate_parameters(generator=2, key_size=1024, backend=default_backend())
        else:
            # 使用提供的p和g生成DH参数
            p = int(p, 16)
            g = int(g, 16)
            parameter_numbers = dh.DHParameterNumbers(p, g)
            parameters = parameter_numbers.parameters(default_backend())

        self.parameters = parameters

        # 动态生成私钥
        self.private_key = self.parameters.generate_private_key()
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
            # 将十六进制字符串转换为整数
            peer_public_key_int = int(peer_public_key_hex, 16)
            # 创建对方的DHPublicKey对象
            parameter_numbers = self.parameters.parameter_numbers()
            peer_public_numbers = dh.DHPublicNumbers(peer_public_key_int, parameter_numbers)
            peer_public_key = peer_public_numbers.public_key(default_backend())

            # 计算共享秘密
            shared_secret = self.private_key.exchange(peer_public_key)

            # 使用SHA-256哈希共享秘密，生成256位的AES密钥
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(shared_secret)
            derived_key = digest.finalize()
            return derived_key
        except Exception as e:
            print(f"Error deriving key: {e}")
            sys.exit(1)

    def get_public_key_hex(self) -> str:
        """
        获取本地公钥的十六进制表示。
        """
        public_numbers = self.public_key.public_numbers()
        y = public_numbers.y
        # 根据密钥长度调整zfill参数
        y_hex = format(y, 'x').zfill(256)
        return y_hex

    def get_parameters_hex(self):
        """
        获取DH参数p和g的十六进制表示。
        """
        parameter_numbers = self.parameters.parameter_numbers()
        p = parameter_numbers.p
        g = parameter_numbers.g
        p_hex = format(p, 'x').zfill(2)  # 确保至少有两个字符，如果不足则补0
        g_hex = format(g, 'x').zfill(2)
        return p_hex, g_hex


def main():
    # 第一步：生成DH参数给TA生成密钥对 模拟 Alice
    crypto_params = FixedDHKeyAESCTR()
    p_hex, g_hex = crypto_params.get_parameters_hex()
    print("生成DH所需要的两个参数: 用于给Alice生成密钥对")
    print("dh_prime (Hex):")
    print(p_hex)
    print("\ndh_base (Hex):")
    print(g_hex)
    print("\n在CA运行的第一步,输入这两个参数，将会在TA中生成一对密钥。\n")

    # 第二步：使用相同的参数初始化加密类 模拟 Bob
    crypto = FixedDHKeyAESCTR(p=p_hex, g=g_hex)

    # 获取Bob的公钥（Hex 格式）
    public_key_hex = crypto.get_public_key_hex()
    print("Bob的公钥 (Hex):")
    print(public_key_hex)
    print("\n在CA运行的第二步, 请将此公钥提供给Alice。")

    # 等待用户输入Alice的公钥
    peer_public_key_hex = input("\n请输入Alice的公钥 (Hex):\n").strip()

    # 验证输入的公钥长度
    if not peer_public_key_hex:
        print("无效的公钥。")
        sys.exit(1)

    # 派生共享密钥
    derived_key = crypto.derive_key(peer_public_key_hex)
    print("派生的密钥:", derived_key.hex())

    # 使用派生的密钥加密消息
    plaintext = b"hello world\n"
    ciphertext = crypto.encrypt(derived_key, plaintext)
    print("密文 (Hex):", ciphertext.hex())
    print("\n请将此密文提供给Alice进行解密。")


if __name__ == '__main__':
    main()
