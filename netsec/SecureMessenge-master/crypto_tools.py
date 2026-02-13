import os
import hashlib
import hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode

# Key Derivation of a symmetric key from password and salt with PBKDF2
def derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


# Message encryption with AES-GCM
def encrypt_message(plaintext: str, key: bytes) -> dict:
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return {
        "iv": b64encode(iv).decode(),
        "ciphertext": b64encode(ciphertext).decode(),
        "tag": b64encode(encryptor.tag).decode()
    }

# Message decryption with AES-GCM
def decrypt_message(enc_data: dict, key: bytes) -> str:
    iv = b64decode(enc_data["iv"])
    tag = b64decode(enc_data["tag"])
    ciphertext = b64decode(enc_data["ciphertext"])

    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()


# Generates an HMAC-SHA256 of the message to ensure integrity
def generate_hmac(message: str, key: bytes) -> str:
    mac = hmac.new(key, message.encode(), hashlib.sha256)
    return mac.hexdigest()

# Verifies HMAC integrity of a message
def verify_hmac(message: str, received_hmac: str, key: bytes) -> bool:
    expected = generate_hmac(message, key)
    return hmac.compare_digest(expected, received_hmac)

# Ephemeral Diffie Hellman exchange (using RFA 3526)
def generate_dh_keypair():
    g = 2
    p = int("""
        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
        29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
        EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
        E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
        EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
        FFFFFFFF FFFFFFFF
    """.replace(" ", "").replace("\n", ""), 16)

    private_key = int.from_bytes(os.urandom(256), 'big') % p
    public_key = pow(g, private_key, p)
    return private_key, public_key, g, p

# Shared secret using Diffie Hellman
def compute_shared_secret(their_public, my_private, p):
    return pow(their_public, my_private, p)