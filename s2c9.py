def pkcs_pad(target_length: int, text: bytes) -> bytes:
    if target_length < len(text):
        raise ValueError(
            'Provided text is longer than target length {}'.format(target_length)
        )

    while len(text) < target_length:
        text += b'\x04'

    return text
