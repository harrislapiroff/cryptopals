import base64


def hex_to_64(value: str) -> bytes:
    return base64.b64encode(bytes.fromhex(value))
