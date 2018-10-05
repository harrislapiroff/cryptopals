"""
Tests to verify success on the Cryptopals challenges
https://cryptopals.com/

WARNING: This test file contains *SPOILERS*. Some Cryptopals tests leave the
solution open-ended (e.g., find the string in this file that decrypts to
English) and the tests were written after the correct solution (e.g., the
English string to be identified) was determined.
"""

import base64
import unittest

import s1c1
import s1c2
import s1c3
import s1c4
import s1c5
import s1c6
import s1c7
import s1c8


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
        self.assertEqual(key, b'X')

    def test_set_1_challenge_4(self):
        "https://cryptopals.com/sets/1/challenges/4"

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

    def test_likely_key_sizes(self):
        "Item 4 from http://cryptopals.com/sets/1/challenges/6"

        with open('challenge-data/s1c6.txt', 'rb') as file:
            key_sizes = s1c6.likely_keysizes(file.read())

        # SPOILER
        self.assertSequenceEqual(
            key_sizes,
            [
                (20, 1.30625), (35, 1.3714285714285714),
                (28, 1.4017857142857142), (23, 1.4130434782608696),
                (32, 1.421875), (38, 1.4407894736842106), (16, 1.44375),
                (37, 1.4527027027027026), (24, 1.4583333333333333), (25, 1.46),
                (7, 1.474025974025974), (13, 1.4807692307692308),
                (39, 1.4807692307692308), (12, 1.4861111111111112),
                (29, 1.4913793103448276), (4, 1.49375),
                (19, 1.506578947368421), (31, 1.5080645161290323),
                (6, 1.5192307692307692), (15, 1.5266666666666666),
                (9, 1.5277777777777777), (11, 1.551948051948052), (2, 1.55625),
                (33, 1.5606060606060606), (8, 1.58125), (5, 1.59375),
                (17, 1.6029411764705883), (21, 1.6031746031746033),
                (22, 1.606060606060606), (40, 1.60625),
                (18, 1.6388888888888888), (36, 1.6388888888888888),
                (14, 1.6428571428571428), (3, 1.6474358974358974),
                (27, 1.6574074074074074), (10, 1.66875), (30, 1.675),
                (26, 1.685897435897436), (34, 1.75),
            ]
        )

    def test_s1c6(self):
        with open('challenge-data/s1c6.txt', 'rb') as file:
            input_bytes = base64.decodebytes(file.read())

        decrypted, key = s1c6.decrypt_by_repeating_key(input_bytes)

        # SPOILER
        self.assertEqual(
            decrypted,
            b"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \nnator X: Bring the noise"
        )
        self.assertEqual(
            key,
            b'Terminator X: Bring the noise'
        )

    def test_s1c7(self):
        with open('challenge-data/s1c7.txt', 'rb') as file:
            input_bytes = base64.decodebytes(file.read())

        decrypted = s1c7.decrypt_aes_ecb('YELLOW SUBMARINE', input_bytes)

        # SPOILER
        self.assertEqual(
            decrypted,
            b"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\x04\x04\x04\x04"
        )

    def test_s1c8(self):
        result = s1c8.set_1_challenge_8('challenge-data/s1c8.txt')

        # SPOILER
        self.assertCountEqual(
            result[0],
            (132, 'd880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a\n')
        )


if __name__ == '__main__':
    unittest.main()
