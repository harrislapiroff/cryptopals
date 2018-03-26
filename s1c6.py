def hamming_distance(b1: bytes, b2: bytes) -> int:
    bitstring1 = ''.join(format(byte, 'b').rjust(8, '0') for byte in b1)
    bitstring2 = ''.join(format(byte, 'b').rjust(8, '0') for byte in b2)

    count = 0
    for bit1, bit2 in zip(bitstring1, bitstring2):
        count += 1 if bit1 != bit2 else 0

    return count
