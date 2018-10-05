import itertools
from typing import List, Tuple

from s1c6 import bytes_to_blocks


def same_blocks(text: bytes) -> int:
    """
    Break a text into 16 block chunks and return the number of those blocks
    that are identical
    """
    blocks = bytes_to_blocks(16, text)
    block_pairs = itertools.combinations(blocks, 2)
    matching_blocks = filter(lambda x: x[0] == x[1], block_pairs)
    return len(list(matching_blocks))


def set_1_challenge_8(filename: str) -> List[Tuple[int, str]]:
    """
    This function is written specifically to the challenge. Given a file name,
    read all the rows from that file and identify one of those rows that is
    encrypted with a AES-ECB

    Returns a tuple of string, encryption character, score
    """
    with open(filename, 'r') as encrypted_file:
        lines_with_repeats = []
        for n, line in enumerate(encrypted_file):
            bytes_line = bytes.fromhex(line)
            same_block_count = same_blocks(bytes_line)
            if same_block_count > 0:
                lines_with_repeats.append((n, line))
        return lines_with_repeats
