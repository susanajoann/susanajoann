#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import os
import json
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# loads key according to tyoe
def load_key(key_file, is_private_key):
    with open(key_file, "rb") as f:
        key_data = f.read()
        if key_file.endswith('.pem'):
            try:
                if is_private_key:
                    return  serialization.load_pem_private_key(key_data, password=None)
                else:
                    return serialization.load_pem_public_key(key_data)
            except ValueError:
                raise ValueError("Failed to laod PEM key")
        if key_file.endswith('.der'):
            try:
                if is_private_key:
                    return  serialization.load_der_private_key(key_data, password=None)
                else:
                    return serialization.load_der_public_key(key_data)
            except ValueError:
                raise ValueError("Failed to laod PEM key")
        else:
            raise ValueError("Unsupported key format. Use .pem or .der")
    
def encrypt_and_sign(public_key_file, private_key_file, text_file, cipher_file):
    # gets public key from file
    public_key = load_key(public_key_file, False)
    # gets private key from file
    private_key = load_key(private_key_file, True)
    # generatres random symmetric key for AES encryption
    symmetric_key = os.urandom(32)
    # sets up the MGF1 mask function for padding
    mgf = padding.MGF1(algorithm=hashes.SHA256())
    # encrypts the key
    encrypted_key = public_key.encrypt(symmetric_key, padding.OAEP(mgf, algorithm=hashes.SHA256(), label=None))
    
    #get plain text
    with open(text_file, "rb") as f:
        plaintext = f.read()
        
    # creates random initialization vector
    iv = os.urandom(16)
    # sets up AES cipher
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    # encrypt the plaintext
    ciphertext = cipher.encryptor().update(plaintext) + cipher.encryptor().finalize()
    # signs the ciphertext with private key
    signature = private_key.sign(ciphertext, padding.PSS(mgf, salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    
    # writes encrypted data
    with open(cipher_file, "wb") as f:
        f.write(json.dumps({
            "encrypted_key" : encrypted_key.hex(),
            "iv" : iv.hex(),
            "ciphertext" : ciphertext.hex(),
            "signature" : signature.hex()}).encode())

def decrypt_and_verify(private_key_file, public_key_file, cipher_file, text_file):
   # loads private key 
    private_key = load_key(private_key_file, True)
    # loads public key
    public_key = load_key(public_key_file, False)
    # loads encrypted data
    with open(cipher_file, "rb") as f:
        data = json.loads(f.read()) 
    
    # gets following info from JSON file
    encrypted_key = bytes.fromhex(data["encrypted_key"])
    iv = bytes.fromhex(data["iv"])
    ciphertext = bytes.fromhex(data["ciphertext"])
    signature = bytes.fromhex(data["signature"])
    # sets up MGF mask
    mgf = padding.MGF1(algorithm=hashes.SHA256()) 
    
    # verify signature 
    try:
        public_key.verify(signature, ciphertext, padding.PSS(mgf, salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        print("Signature is valid.")
    # throws exception if signature is not valid
    except Exception as e:
        raise ValueError("signature verification failed.") from e
    
    # decrypt symmetric key 
    symmetric_key = private_key.decrypt(encrypted_key, padding.OAEP(mgf, algorithm=hashes.SHA256(), label=None))      
    
    # creates AES cipher for decryption
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    # gets plaintext from decryption
    plaintext = cipher.decryptor().update(ciphertext) + cipher.decryptor().finalize()
    
    # puts plain text into file
    with open(text_file, "wb") as f:
        f.write(plaintext)
        
def main():
    # sets up arg parser
    parser = argparse.ArgumentParser()
    # this group ensures only -e or -d is done
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", action="store_true")
    group.add_argument("-d", "--decrypt", action="store_true")
    
    parser.add_argument("destination_key", type=str)
    parser.add_argument("sender_key", type=str)
    parser.add_argument("input", type=str)
    parser.add_argument("output", type=str)
    
    args = parser.parse_args()

    # sends encryption to correct function if -e specified
    if args.encrypt:
        encrypt_and_sign(args.destination_key, args.sender_key, args.input, args.output)
    # sends decryption to correct function if -d specified
    elif args.decrypt:
        decrypt_and_verify(args.destination_key, args.sender_key, args.input, args.output)
        
if __name__ == "__main__":
    main()
    