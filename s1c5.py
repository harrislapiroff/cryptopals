import base64


def repeating_key_xor(value: bytes, key: bytes) -> bytes:
    acc = b''
    for i, v in enumerate(value):
        acc = acc + bytes([v ^ key[i % len(key)]])
    return acc
