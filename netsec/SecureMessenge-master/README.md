client.py: The client.py reads the config file and connects a socket to the 
host and port in the file. Then the client builds and sends the authenticaion message
with the username and password to the server. The client then receives thread for
handiling messages from the server. It derives a shared key for a secure session and 
decrypts message from the encrypted one. It also creates a loop to get user inputs such as 
list and send. If the message is sent to a target without a session_key, a key exchange is started.

config.ini: has the host and port to start the connection to the server

crypto_tools: uses PBKDF2HMAC with SHA256 and a salt to derive a key. It encrypts a message 
using AES with GCM mode and an iv. It decrpts a message using the iv and tag. It also 
generates a hmac, verifies it,  can generate a dh keypair, and compute a shared secret.

protocol.py: Builds a json message with type, sender, recipient, payload, and hmac info. However, 
only message type is a requirted field. It parses a message by using json load. Lastly, it 
prints the message using json dump and parsing it. 

requirements.txt: states libraries used in the code. 

server.py: gets the message, username and password, and sees if they are a part of the system.
It verifies the user with their verifier in file from the derived key from password. If the user is
new, it creates the user and verifier with the password they submitted. It then
handles the user's requests, List and message. It also starts the server on the server and host
given in config.ini

users.json: includes user data for verification. If a user isn't on this list and someone logs in as a user with a specified password for the first time, that user will be added to this json file alongside a salt and verifier for their password.


Running the Program:

Modify the config.ini if needed for the port as well as the host. Launch a terminal and start the server.py file. On another terminal, start the client.py. On the client side, enter in a Username and Password. If that username is not already registered with that specified password, it will make a new entry for a user and users.json and will save that for subsequent logins for that user. Once the client logs in, they will be able to use these commands:

list - Lists the users on the server
send <User> <Message> - Sends the specified user a message
logout - logs the user out of server.
