from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
from gmssl import sm3
from binascii import hexlify, unhexlify
from gmssl import sm2

key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
iv = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
private_key_hex = '38a73c745b32f3a8e72d9a7d283d9d813c01302bda6746a2b32307f9302025e5'
public_key_hex = '0471a5e2584786a769d52d4736c3ad88251d14b9d37c6ff3e0615c3bdad66a248ce4b9c85974405dc3026ffd29dae23eea47310272cc0895f31b7d69933a1e35e4'

value = "password"


def sm4_en_enc(plain):
    # 字符串转二进制
    key_binary = unhexlify(key)
    value_binary = plain.encode()
    # 初始化CryptSM4对象
    crypt_sm4 = CryptSM4()
    # 设置密钥和模式
    crypt_sm4.set_key(key_binary, SM4_ENCRYPT)
    # 加密
    encrypt_value = crypt_sm4.crypt_ecb(value_binary)
    # 二进制转字符串
    encrypt_value = hexlify(encrypt_value).decode('ascii')
    return encrypt_value


def sm4_de_enc(cipher):
    # 字符串转二进制
    key_binary = unhexlify(key)
    cipher_binary = unhexlify(cipher)
    # 初始化CryptSM4对象
    crypt_sm4 = CryptSM4()
    # 设置解密模式
    crypt_sm4.set_key(key_binary, SM4_DECRYPT)
    # 解密
    binary_plain = crypt_sm4.crypt_ecb(cipher_binary)
    # 二进制转字符串
    decrypt_value = binary_plain.decode()


def sm4_en_cbc(plain):
    # 字符串转二进制
    key_binary = unhexlify(key)
    iv_binary = unhexlify(iv)
    value_binary = plain.encode()
    # 初始化CryptSM4对象
    crypt_sm4 = CryptSM4()
    # 设置密钥和模式
    crypt_sm4.set_key(key_binary, SM4_ENCRYPT)
    # 加密
    encrypt_value = crypt_sm4.crypt_cbc(iv_binary, value_binary)
    # 设置解密模式
    crypt_sm4.set_key(key_binary, SM4_DECRYPT)
    # 二进制转字符串
    encrypt_value = hexlify(encrypt_value).decode('ascii')
    print(encrypt_value)
    return encrypt_value


def sm4_de_cbc(cipher):
    # 字符串转二进制
    key_binary = unhexlify(key)
    iv_binary = unhexlify(iv)
    cipher_binary = unhexlify(cipher)
    # 初始化CryptSM4对象
    crypt_sm4 = CryptSM4()
    # 设置解密模式
    crypt_sm4.set_key(key_binary, SM4_DECRYPT)
    # 解密
    binary_decrypt_value = crypt_sm4.crypt_cbc(iv_binary, cipher_binary)
    # 二进制转字符串
    decrypt_value = binary_decrypt_value.decode()
    print(decrypt_value)
    return decrypt_value


def sm3_digest(plain):
    # 字符串转二进制
    value_binary = plain.encode()
    # 二进制转二进制字节数组
    bytearray_value = bytearray(value_binary)
    # 生成摘要
    digest = sm3.sm3_hash(bytearray_value)
    return digest


def sm2_encrypt(plain):
    # 将字符串转化为转换为bytes
    binary_value = plain.encode()
    # 初始化CryptSM2对象
    # mode: 0 - C1C2C3, 1 - C1C3C2
    sm2_crypt = sm2.CryptSM2(
        public_key=public_key_hex,
        private_key=private_key_hex,
        mode=1
    )
    enc_data = sm2_crypt.encrypt(binary_value)
    # 二进制转字符串
    encrypt_value = hexlify(enc_data).decode('ascii')
    return encrypt_value


def sm2_decrypt(ciper):
    # 将字符串转化为转换为bytes
    binary_ciper = unhexlify(ciper)
    # 初始化CryptSM2对象
    # mode: 0 - C1C2C3, 1 - C1C3C2
    sm2_crypt = sm2.CryptSM2(
        public_key=public_key_hex,
        private_key=private_key_hex,
        mode=1
    )
    dec_data = sm2_crypt.decrypt(binary_ciper)
    # 二进制转字符串
    decrypt_value = dec_data.decode()
    return decrypt_value


if __name__ == "__main__":
    sm4_de_enc(sm4_en_enc(value))
    sm4_de_cbc(sm4_en_cbc(value))
    sm3_digest(value)
    sm2_decrypt(sm2_encrypt(value))
