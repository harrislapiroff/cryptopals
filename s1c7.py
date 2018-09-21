from Crypto.Cipher import AES


def decrypt_aes_ecb(key: bytes, body: bytes):
    decryption_suite = AES.new(key, AES.MODE_ECB)
    return decryption_suite.decrypt(body)
