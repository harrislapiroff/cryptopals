import base64


def xor(b1: bytes, b2: bytes) -> bytes:
    xored = bytes(
        x ^ y for x, y in
        zip(base64.decodebytes(b1), base64.decodebytes(b2))
    )
    return xored
