
import unittest
import os
import json
from crypto_tools import *
from protocol import *

class TestCryptoTools(unittest.TestCase):

    private_key, public_key, q, p = generate_dh_keypair()
    private_key2, public2, q2, p2 = generate_dh_keypair()
    shared_key = compute_shared_secret(public2, private_key, p)% (1 << 128)
    shared_key = shared_key.to_bytes(16, "big")
    
    def test_key_generation_and_encryption(self):
        message = "Hello, Secure World!" 
        ciphertext = encrypt_message(message, self.shared_key)
        plaintext = decrypt_message(ciphertext, self.shared_key)
        self.assertEqual(plaintext, message)
        


if __name__ == '__main__':
    unittest.main()
