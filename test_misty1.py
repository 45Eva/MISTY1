import unittest

from misty1 import GenerateRoundKeys, EncryptBlock, DecryptBlock

"""
    Допоміжна функція.
    Перетворює список K' (8 слів по 16 біт)
    у суцільний hex-рядок, як у стандарті.
    """
def _kprime_to_hex(rk: dict) -> str:
    kp = rk["Kp"]
    return "".join(f"{x & 0xFFFF:04x}" for x in kp)

"""
    Тести для перевірки коректності реалізації алгоритму MISTY1
    згідно стандарту ISO/IEC 18033-3.
    """
class TestMISTY1(unittest.TestCase):
    
    # Тестові набори з стандарту
    TEST_VECTORS = [
        {
            "K":  "00112233445566778899aabbccddeeff",
            "P":  "0123456789abcdef",
            "C":  "8b1da5f56ab3d07c",
            "Kp": "cf518e7f5e29673acdbc07d6bf355e11",
        },
        {
            "K":  "414afd99bb577ee69df58cc8fb4e6888",
            "P":  "9fc302e281310e90",
            "C":  "15c270974b9b9163",
            "Kp": "c7bd6e012268237a4389305a1b360b8c",
        },
        {
            "K":  "3c54aed9a5389c947167db9d97c6967a",
            "P":  "032c4a4a100ee807",
            "C":  "3346cb8c779cf2de",
            "Kp": "7c8e13ebfe7648050c9097934205662b",
        },
        {
            "K":  "d3f11a6d25f1b3866fdada0b5e53fa17",
            "P":  "db9e3218402023f3",
            "C":  "b2dd1595a450bc98",
            "Kp": "f011d035ac920f832f69bcf7b860d4f0",
        },
        {
            "K":  "5f87f88ec7641d83af03fd8327821046",
            "P":  "6553de24c0dd900b",
            "C":  "60081e65cb7c2b84",
            "Kp": "3736172d7421c91401596db29d3d5536",
        },
    ]

    """
        Перевіряємо, що ключовий розклад (K')
        обчислюється так само, як у стандарті.
        """
    def test_key_schedule_kprime(self):
        
        for tv in self.TEST_VECTORS:
            rk = GenerateRoundKeys(tv["K"])
            kp_hex = _kprime_to_hex(rk)

            self.assertEqual(
                kp_hex.lower(),
                tv["Kp"].lower()
            )

    """
        Перевіряємо, що EncryptBlock
        дає правильний шифротекст для відомих даних.
        """
    def test_encrypt_matches_standard(self):
        
        for tv in self.TEST_VECTORS:
            key = bytes.fromhex(tv["K"])
            plaintext = bytes.fromhex(tv["P"])
            ciphertext_expected = bytes.fromhex(tv["C"])

            ciphertext = EncryptBlock(plaintext, key)

            self.assertEqual(ciphertext, ciphertext_expected)

    """
        Перевіряємо, що DecryptBlock
        правильно відновлює відкритий текст.
        """
    def test_decrypt_matches_standard(self):
        
        for tv in self.TEST_VECTORS:
            key = bytes.fromhex(tv["K"])
            ciphertext = bytes.fromhex(tv["C"])
            plaintext_expected = bytes.fromhex(tv["P"])

            plaintext = DecryptBlock(ciphertext, key)

            self.assertEqual(plaintext, plaintext_expected)

    """
        Додаткова перевірка:
        якщо зашифрувати, а потім розшифрувати,
        маємо отримати початкові дані.
        """
    def test_encrypt_and_decrypt_are_inverse(self):
        
        for tv in self.TEST_VECTORS:
            key = bytes.fromhex(tv["K"])
            plaintext = bytes.fromhex(tv["P"])

            ciphertext = EncryptBlock(plaintext, key)
            decrypted = DecryptBlock(ciphertext, key)

            self.assertEqual(decrypted, plaintext)

    """
        EncryptBlock має відхиляти блоки,
        довжина яких не дорівнює 8 байтів.
        """
    def test_wrong_block_length_encrypt(self):
        
        key = bytes.fromhex(self.TEST_VECTORS[0]["K"])

        with self.assertRaises(ValueError):
            EncryptBlock(b"\x00" * 7, key)

        with self.assertRaises(ValueError):
            EncryptBlock(b"\x00" * 9, key)

    """
        DecryptBlock також має відхиляти
        блоки неправильної довжини.
        """
    def test_wrong_block_length_decrypt(self):
        
        key = bytes.fromhex(self.TEST_VECTORS[0]["K"])

        with self.assertRaises(ValueError):
            DecryptBlock(b"\x00" * 7, key)

        with self.assertRaises(ValueError):
            DecryptBlock(b"\x00" * 9, key)


if __name__ == "__main__":
    unittest.main(verbosity=2)
