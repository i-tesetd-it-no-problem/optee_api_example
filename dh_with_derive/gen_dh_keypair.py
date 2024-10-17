from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives import serialization


def bytes_to_c_array(data, name, size_macro):
    array_str = f"uint8_t {name}[{size_macro}] = {{\n"

    for i in range(0, len(data), 16):
        array_str += '    ' + ', '.join(f'0x{byte:02X}' for byte in data[i:i + 16]) + ',\n'

    array_str += "};\n\n"
    return array_str


def generate_ecdh_keys(curve):
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    return private_key, public_key


def generate_x25519_keys():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def write_keys_to_source_and_header_files():
    with open("dh_keys.h", "w", encoding="utf-8") as header_file, \
            open("dh_keys.c", "w", encoding="utf-8") as source_file:

        header_file.write("/* 自动生成的密钥数组和大小宏定义，用于测试密钥交换算法 请勿修改 */\n")
        header_file.write("#ifndef _DH_KEYS_H\n")
        header_file.write("#define _DH_KEYS_H\n\n")
        header_file.write("#include <stdint.h>\n\n")

        key_definitions = [
            ("ecdh_p192", ec.SECP192R1()),
            ("ecdh_p224", ec.SECP224R1()),
            ("ecdh_p256", ec.SECP256R1()),
            ("ecdh_p384", ec.SECP384R1()),
            ("ecdh_p521", ec.SECP521R1()),
            ("x25519", None),
        ]

        key_arrays = []
        size_definitions = []

        for key_name, curve in key_definitions:
            if key_name.startswith("ecdh"):
                private_key_ca, public_key_ca = generate_ecdh_keys(curve)

                private_bytes_ca = private_key_ca.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )

                public_bytes_ca = public_key_ca.public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint
                )

            elif key_name == "x25519":
                private_key_ca, public_key_ca = generate_x25519_keys()

                private_bytes_ca = private_key_ca.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                )

                public_bytes_ca = public_key_ca.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )

            ca_private_size_macro = f"CA_{key_name.upper()}_PRIVATE_KEY_SIZE"
            ca_public_size_macro = f"CA_{key_name.upper()}_PUBLIC_KEY_SIZE"

            size_definitions.append(f"#define {ca_private_size_macro} {len(private_bytes_ca)}  /* CA侧私钥大小 */\n")
            size_definitions.append(f"#define {ca_public_size_macro} {len(public_bytes_ca)}   /* CA侧公钥大小 */\n\n")

            key_arrays.append(bytes_to_c_array(private_bytes_ca, f"ca_{key_name}_private_key", ca_private_size_macro))
            key_arrays.append(bytes_to_c_array(public_bytes_ca, f"ca_{key_name}_public_key", ca_public_size_macro))

        for size_def in size_definitions:
            header_file.write(size_def)

        header_file.write("\n")

        for key_name, _ in key_definitions:
            header_file.write(
                f"extern uint8_t ca_{key_name}_private_key[{f'CA_{key_name.upper()}_PRIVATE_KEY_SIZE'}];\n")
            header_file.write(
                f"extern uint8_t ca_{key_name}_public_key[{f'CA_{key_name.upper()}_PUBLIC_KEY_SIZE'}];\n\n")

        header_file.write("#endif /* _DH_KEYS_H */\n")

        source_file.write("/* 自动生成的密钥数组和大小宏定义，用于测试密钥交换算法 请勿修改 */\n")
        source_file.write("#include \"dh_keys.h\"\n\n")

        for key_array in key_arrays:
            source_file.write(key_array)


write_keys_to_source_and_header_files()
