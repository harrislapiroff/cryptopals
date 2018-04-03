from typing import Tuple

from s1c3 import find_single_character_decryption_key


def set_1_challenge_4(filename: str) -> Tuple[bytes, str, float]:
    """
    This function is written specifically to the challenge. Given a file name,
    read all the rows from that file and identify one of those rows that is
    encrypted with a single character

    Returns a tuple of string, encryption character, score
    """
    decrypted_lines = []
    with open(filename, 'r') as encrypted_file:
        for line in encrypted_file:
            # Get best possible decryption for this line
            decrypted_lines.append(
                find_single_character_decryption_key(
                    bytes.fromhex(line.rstrip())
                )
            )
    # Now find the best result of our best results
    decrypted_lines.sort(key=lambda x: x[2])
    return decrypted_lines[0]
