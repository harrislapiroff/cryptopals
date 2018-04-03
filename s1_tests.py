"""
Tests to verify success on the Cryptopals challenges
https://cryptopals.com/

WARNING: This test file contains *SPOILERS*. Some Cryptopals tests leave the
solution open-ended (e.g., find the string in this file that decrypts to
English) and the tests were written after the correct solution (e.g., the
English string to be identified) was determined.
"""

import unittest

import s1c1
import s1c2
import s1c3
import s1c4
import s1c5
import s1c6


class CryptoPalsTestCase(unittest.TestCase):
    def test_hex_to_64(self):
        "https://cryptopals.com/sets/1/challenges/1"
        self.assertEqual(
            s1c1.hex_to_64(
                '49276d206b696c6c696e6720796f757220627261696e206c696b652061207'
                '06f69736f6e6f7573206d757368726f6f6d'
            ),
            b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
        )

    def test_xor(self):
        "https://cryptopals.com/sets/1/challenges/2"
        self.assertEqual(
            s1c2.xor(
                s1c1.hex_to_64('1c0111001f010100061a024b53535009181c'),
                s1c1.hex_to_64('686974207468652062756c6c277320657965')
            ).hex(),
            '746865206b696420646f6e277420706c6179'
        )

    def test_english_like(self):
        """
        The english string should score lower than the gibberish one--this
        test is for my own verification and does not comprise any challenge on
        its own
        """
        self.assertLess(
            s1c3.like_english_score(
                b'Call me Ishmael. Some years ago- never mind how long '
                b'precisely- having little or no money in my purse, and '
                b'nothing particular to interest me on shore, I thought I '
                b'would sail about a little and see the watery part of the '
                b'world.'
            ),
            s1c3.like_english_score(
                b'sfdhsuit47oroAS(y53hfs;dt8o4w;otnghow;t4f)dfet3tgh8lfdhfluis'
                b'a'
            )
        )

    def test_single_character_decryption(self):
        "https://cryptopals.com/sets/1/challenges/3"
        decrypted, key, _ = s1c3.find_single_character_decryption_key(
            bytes.fromhex(
                '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a3'
                '93b3736'
            )
        )
        # SPOILER
        self.assertEqual(decrypted, b"Cooking MC's like a pound of bacon")
        self.assertEqual(key, 'X')

    def test_set_1_challenge_4(self):
        decrypted, _, _ = s1c4.set_1_challenge_4('challenge-data/s1c4.txt')
        # SPOILER
        self.assertEqual(decrypted, b'Now that the party is jumping\n')

    def test_repeating_key_xor(self):
        "http://cryptopals.com/sets/1/challenges/5"

        xored = s1c5.repeating_key_xor(
            b'Burning \'em, if you ain\'t quick and nimble\n'
            b'I go crazy when I hear a cymbal',
            b'ICE'
        )
        self.assertEqual(
            xored.hex(),
            '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2622632'
            '4272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b202831'
            '65286326302e27282f'
        )

    def test_hamming_distance(self):
        "Item 2 from http://cryptopals.com/sets/1/challenges/6"
        self.assertEqual(
            s1c6.hamming_distance(
                b'this is a test',
                b'wokka wokka!!!'
            ),
            37
        )

if __name__ == '__main__':
    unittest.main()
