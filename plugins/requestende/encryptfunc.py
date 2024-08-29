import chardet
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT, ZERO
from gmssl import sm3, sm4
from binascii import hexlify, unhexlify
from gmssl import sm2

# 静态参数
KEY = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
IV = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
PRIVATE_KEY_HEX = ''
PUBLIC_KEY_HEX = ''

value = "password"


def sm4_en_cbc(plain):
    # 字符串转二进制
    key_binary = unhexlify(KEY)
    iv_binary = unhexlify(IV)
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

    return encrypt_value


def sm4_de_cbc(cipher):
    # 字符串转二进制
    key_binary = unhexlify(KEY)
    iv_binary = unhexlify(IV)
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
        public_key=PUBLIC_KEY_HEX,
        private_key=PRIVATE_KEY_HEX,
        mode=0
    )
    enc_data = sm2_crypt.encrypt(binary_value)
    # 二进制转字符串
    encrypt_value = hexlify(enc_data).decode('ascii')
    return encrypt_value


def sm2_decrypt(ciper):
    if ciper[:2] == '04':
        ciper = ciper[2:]
    # 将密文转化为转换为bytes
    # binary_ciper = unhexlify(ciper)
    binary_ciper = bytes.fromhex(ciper)

    # 初始化CryptSM2对象
    # mode: 0 - C1C2C3, 1 - C1C3C2
    sm2_crypt = sm2.CryptSM2(
        public_key=PUBLIC_KEY_HEX,
        private_key=PRIVATE_KEY_HEX,
        mode=0
    )
    dec_data = sm2_crypt.decrypt(binary_ciper)

    # 二进制转字符串
    # decrypt_value = dec_data.decode()
    # 解密为16进制字符串
    decrypt_value = dec_data.decode()

    return decrypt_value

def sm4_de_enc(cipher, sm4_key=KEY):
    # 字符串转二进制
    # key_binary = unhexlify(sm4_key)
    key_binary = bytes.fromhex(sm4_key)
    cipher_binary = unhexlify(cipher)
    # 初始化CryptSM4对象 设置-1使用不进行填充解密
    crypt_sm4 = CryptSM4(sm4.SM4_ENCRYPT, -1)
    # 设置解密模式
    crypt_sm4.set_key(key_binary, SM4_DECRYPT)
    # 解密
    binary_plain = crypt_sm4.crypt_ecb(cipher_binary)
    # 二进制转字符串
    decrypt_value = binary_plain.decode()
    cleaned_string = decrypt_value.replace('\x00', '')
    return cleaned_string

def sm4_en_enc(plain, sm4_key=KEY):
    # 字符串转二进制
    key_binary = unhexlify(sm4_key)
    value_binary = plain.encode()
    # 初始化CryptSM4对象 填充模式 sm4.ZERO, sm4.PKCS7, -1, -1为不填冲 sm4.SM4_ENCRYPT, sm4.PKCS7
    crypt_sm4 = CryptSM4()
    # 设置密钥和模式
    crypt_sm4.set_key(key_binary, SM4_ENCRYPT)
    # 加密
    encrypt_value = crypt_sm4.crypt_ecb(value_binary)
    # 二进制转字符串
    encrypt_value = encrypt_value.hex()
    return encrypt_value


if __name__ == "__main__":
    cipher = "c1fc77748e91b6c08f698dd1e8cdf820853e5abebe278ce4971e7ab40aac59624f50223c5fb1f5798bf123e3759a4e099c3ea361f4f4d908db50e5d50238ca042934991a8773c599efb45775fb48b28515bf83cae34a60dbe3f24a8ab888972b818ddc557555ec8b47e6edb38a798c510f175b0fc79df796dcef579c4182e6adbf49ed6cc645775bf849e25a0675347ed1fe3f968aeabd45314eb43b1179b290bad405f5f5abef3d6f27897859aa822cdec7dad51291564bbe757fd2678f77f064390a10373b75b3249747a6508f4ca5bb71065247bbe69a3ca73d5ae62a28b052baacbd2749f320f60bce867b15a1b795c465151f0c53845296aee0925d965a"
    key = "95af0c9cbbb449fa7f8c5ff5c368def1"
    a = sm4_de_enc(cipher, key)
    c = '{"order":"asc","limit":1,"offset":0},AAAAAAAAAAAAAAAA89e4cc7cf482a9de96eb290982b8841e6b81113e8fe0448843e421ff42e9f3d9'
    b = sm4_en_enc(a)
    d = sm4_de_enc(b)
    print(a)
    print(b)
    print(d)
    # sm4_de_enc(sm4_en_enc(value))
    # sm4_de_cbc(sm4_en_cbc(value))
    # sm3_digest(value)
    # sm2_decrypt(sm2_encrypt(value))