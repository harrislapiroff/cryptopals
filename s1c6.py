import base64
from itertools import zip_longest

from typing import Tuple, List

from s1c3 import (
    find_single_character_decryption_key,
)


def hamming_distance(b1: bytes, b2: bytes) -> int:
    bitstring1 = ''.join(format(byte, 'b').rjust(8, '0') for byte in b1)
    bitstring2 = ''.join(format(byte, 'b').rjust(8, '0') for byte in b2)

    count = 0
    for bit1, bit2 in zip(bitstring1, bitstring2):
        count += 1 if bit1 != bit2 else 0

    return count


def likely_keysizes(
    body: bytes,
    min_key_size=2,
    max_key_size=40
) -> List[Tuple[int, float]]:
    """
    Given a base64 encoded body, make a list of key sizes in order by
    calculating the hamming distance between the first two strings of that key
    size in the body

    Returns a tuple of two-tuples of the format
    (key size, normalized edit distance), sorted with the lowest edit distances
    at the top

    (See http://cryptopals.com/sets/1/challenges/6 step 3)
    """

    decoded = base64.decodebytes(body)

    attempted_key_sizes = []
    for key_size in range(min_key_size, max_key_size + 1):
        first_string = decoded[0:key_size]
        second_string = decoded[key_size:key_size * 2]
        attempted_key_sizes.append((
            key_size,
            hamming_distance(first_string, second_string) / key_size,
        ))

    attempted_key_sizes.sort(key=lambda x: x[1])
    return attempted_key_sizes


def decrypt_by_repeating_key_with_size(
    body: bytes,
    size: int
) -> Tuple[bytes, bytes]:
    """
    Given a base64 encoded body and a specific key size, attempt to deduce
    the key used with repeating key encryption
    """

    # Honestly I don't fully understand why this works. Seems like functional
    # magic to me.
    # See:
    # https://stackoverflow.com/questions/9475241/split-string-every-nth-character#comment75857079_9475538
    #
    # Also, should I really be filling values with 0 if there's a remainder????
    blocks_as_ints = list(zip_longest(*[iter(body)] * size, fillvalue=0))

    # Transpose the blocks so that we can get the first characters from each
    # block, the second characters from each block, the third characters
    # from each block, etc.
    columns = list(zip(*blocks_as_ints))
    decryption_key = b''
    decrypted_columns = []
    for column in columns:
        column_as_bytes = bytes(column)
        decrypted_column, column_key, _ = find_single_character_decryption_key(
            column_as_bytes
        )
        decryption_key = decryption_key + column_key
        decrypted_columns.append(list(decrypted_column))

    # Transpose the decrypted columns back into blocks
    decrypted_blocks = list(zip(*decrypted_columns))
    decrypted_string = b''.join(bytes(x) for x in decrypted_blocks)

    return decrypted_string, decryption_key


def decrypt_by_repeating_key(
    body: bytes
):
    """
    Given a base64 encoded body, attempt to determine the repeating key
    that it was encrypted with and decrypt it
    """

    ranked_key_sizes = likely_keysizes(body)

    for key_size, _ in ranked_key_sizes[0:20]:
        decrypted, key = decrypt_by_repeating_key_with_size(body, key_size)
        # None of these results look like english and I don't know why!
        print(decrypted)
        print(key)
