"""
Tests to verify success on the Cryptopals challenges
https://cryptopals.com/

WARNING: This test file contains *SPOILERS*. Some Cryptopals tests leave the
solution open-ended (e.g., find the string in this file that decrypts to
English) and the tests were written after the correct solution (e.g., the
English string to be identified) was determined.
"""

import unittest

import s2c9


class CryptoPalsTestCase(unittest.TestCase):
    def test_s2c9(self):
        self.assertEqual(
            s2c9.pkcs_pad(20, b'YELLOW SUBMARINE'),
            b'YELLOW SUBMARINE\x04\x04\x04\x04'
        )


if __name__ == '__main__':
    unittest.main()
