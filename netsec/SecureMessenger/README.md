client.py: The client.py reads the config file and connects a socket to the 
host and port in the file. Then the client builds and sends the authenticaion message
with the username and password to the server. The client then receives thread for
handiling messages from the server. It derives a shared key for a secure session and 
decrypts message from the encrypted one. It also creates a loop to get user inputs such as 
list and send. If the message is sent to a target without a session_key, a key exchange is started.

config.ini: has the host and port to start the connection to the server

create_user.py: creates a user from a username and password. It derives a key (using cypto_tools)
and then saves the username and its salt and verifier to user.json. 

crypto_tools: uses PBKDF2HMAC with SHA256 and a salt to derive a key. It encrypts a message 
using AES with GCM mode and an iv. It decrpts a message using the iv and tag. It also 
generates a hmac, verifies it,  can generate a dh keypair, and compute a shared secret.

protocol.py: Builds a json message with type, sender, recipient, payload, and hmac info. However, 
only message type is a requirted field. It parses a message by using json load. Lastly, it 
prints the message using json dump and parsing it. 

requirements.txt: states libraries used in the code. 

server.py: gets the message, username and password, and sees if they are a part of the system.
It verifies the user with their verifier in file from the derived key from password. It then
handles the user's requests, List and message. It also starts the server on the server and host
given in config.ini

user.json: includes user data for verification.
