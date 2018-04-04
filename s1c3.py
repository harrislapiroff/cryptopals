from collections import defaultdict

from typing import Tuple


ENGLISH_CHARACTER_FREQUENCY = {
    'a': 0.08167,
    'b': 0.01492,
    'c': 0.02782,
    'd': 0.04253,
    'e': 0.12702,
    'f': 0.02228,
    'g': 0.02015,
    'h': 0.06094,
    'i': 0.06966,
    'j': 0.00153,
    'k': 0.00772,
    'l': 0.04025,
    'm': 0.02406,
    'n': 0.06749,
    'o': 0.07507,
    'p': 0.01929,
    'q': 0.00095,
    'r': 0.05987,
    's': 0.06327,
    't': 0.09056,
    'u': 0.02758,
    'v': 0.00978,
    'w': 0.02360,
    'x': 0.00150,
    'y': 0.01974,
    'z': 0.00074,
}


def single_character_xor(b: bytes, i: int) -> bytes:
    xored = bytes(x ^ i for x in b)
    return xored


def like_english_score(b: bytes) -> float:
    """
    Return a score that measures how the character distribution of a string
    diverges from the character distribution in English

    Lower scores are more English-like
    """

    counts = defaultdict(lambda: 0)
    total_chars = 0
    for x in b:
        key = chr(x).lower()
        # In an ideal world we'd include frequencies for spaces and punctuation
        # but unfortunately we don't have that data right now, so we discard
        # those characters instead.
        if chr(x) not in ENGLISH_CHARACTER_FREQUENCY:
            continue
        total_chars += 1
        counts[key] += 1

    # If there are no english characters, it's probably not english
    if total_chars == 0:
        return 2

    score = 0
    for character, frequency in ENGLISH_CHARACTER_FREQUENCY.items():
        # Add the magnitude of divergence between the current character's
        # frequency in the string and the current character's frequency in
        # English
        score += abs(frequency - (counts[character] / total_chars))

    return score


def find_single_character_decryption_key(b: bytes) -> Tuple[bytes, bytes, float]:
    """
    Provided a bytestring, attempt decryption with single-character keys,
    assign them an english-likeness score, and return the lowest scoring string

    Returns a tuple of string, encryption character, score
    """

    possibilities = []
    for x in range(0, 255):
        decrypted = single_character_xor(b, x)
        possibilities.append(
            (decrypted, bytes([x]), like_english_score(decrypted))
        )

    # Sort the list in order of score and return the first item, which is the
    # most likely to be English
    possibilities.sort(key=lambda x: x[2])
    return possibilities[0]
