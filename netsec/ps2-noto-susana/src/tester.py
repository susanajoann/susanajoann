#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import subprocess
import tempfile
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keys():
    """Generate RSA public and private keys."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem

def run_test():
    """Test encryption and decryption using the fcrypt script."""
    # Generate RSA keys for sender and recipient
    private_key_sender, public_key_sender = generate_rsa_keys()
    private_key_dest, public_key_dest = generate_rsa_keys()

    # Create temporary files for keys and data

    with open("tester_files/sender_priv_file.pem", "wb") as f:
        f.write(private_key_sender)
    with open("tester_files/sender_pub_file.pem", "wb") as f:
        f.write(public_key_sender)
    with open("tester_files/dest_priv_file.pem", "wb") as f:
         f.write(private_key_dest)
    with open("tester_files/dest_pub_file.pem", "wb") as f:
         f.write(public_key_dest)


        # Write sample plaintext
    sample_text = b"This is a test file for encryption and signing."
    with open("tester_files/plaintext", "wb") as f:
        f.write(sample_text)
    

if __name__ == "__main__":
    run_test()
