import sys
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class FixedX25519KeyAESCTR:
    def __init__(self):
        """
        初始化 X25519 ECDH 参数并生成密钥对。
        """
        # 生成私钥
        self.private_key = x25519.X25519PrivateKey.generate()
        # 获取公钥
        self.public_key = self.private_key.public_key()

    def encrypt(self, key: bytes, plaintext: bytes) -> bytes:
        """
        使用派生的密钥进行 AES-CTR 加密。
        固定 IV 为 16 字节的 0x5A。
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
            peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
            # 计算共享秘密
            shared_secret = self.private_key.exchange(peer_public_key)
            # 使用 SHA-256 哈希共享秘密，生成 AES 密钥
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
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return public_bytes.hex()


def generate_keypair(crypto: FixedX25519KeyAESCTR):
    """
    生成本地密钥对，并打印公钥的十六进制表示。
    """
    public_key_hex = crypto.get_public_key_hex()
    print("X25519 公钥 (Hex):")
    print(public_key_hex)
    print("\n请将此公钥提供给对方（Alice/Bob）。")


def generate_shared_key(crypto: FixedX25519KeyAESCTR):
    """
    输入对方的公钥，派生共享密钥。
    """
    peer_public_key_hex = input("\n请输入对方的公钥 (Hex):\n").strip()

    # 验证输入的公钥长度
    if len(peer_public_key_hex) != 64:  # X25519 公钥应为 32 字节，即 64 个十六进制字符
        print("Invalid public key length for X25519. Expected 64 hex characters.")
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
    # 初始化 X25519 加密类
    crypto = FixedX25519KeyAESCTR()

    # 生成密钥对并打印公钥
    generate_keypair(crypto)

    # 派生共享密钥
    generate_shared_key(crypto)


if __name__ == '__main__':
    main()
