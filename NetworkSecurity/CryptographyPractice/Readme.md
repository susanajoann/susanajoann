This is a python application that can be used to encrypt and sign a single file as well as authentication a signature and decrypt a file.
The sender knows the public key of the destination and has their own private key. DER and PEM keys can be used. 

For encryption and signatures, the command-line syntax is:
python fcrypt.py -e destination_public_key_filename sender_private_key_filename input_plaintext_file ciphertext_file

For decryption and signature verification the command-line syntax is:
python fcrypt.py -d destination_private_key_filename sender_public_key_filename ciphertext_file output_plaintext_file

Please keep in mind this was a school project and is not perfect by any means. I recieved feedback that tampering with 
the IV is possible since it is not protected by the signature. 
