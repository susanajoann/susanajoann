import socket
import json
from protocol import *
from crypto_tools import *
import getpass
import configparser
import threading

# Reads the config to connect to
config = configparser.ConfigParser()
config.read("config.ini")
host = config["server"]["host"]
port = int(config["server"]["port"])

session_keys = {}
incoming_dh = {}

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))

# Diffie Hellman key exchange with server
privA, pubA, g, p = generate_dh_keypair()
key_exchange_msg = build_message("KEY_EXCHANGE", sender="preauth", payload={"pubA": pubA, "g": g, "p": p})
s.send(key_exchange_msg.encode())
raw = s.recv(4096).decode()
msg = parse_message(raw)
pubB = msg["payload"]["pubB"]
shared_secret = compute_shared_secret(pubB, privA, p)
session_key = derive_key(str(shared_secret), salt=b"prelogin")

# Prompts user login and get the credentials
username = input("Username: ")
password = getpass.getpass("Password: ")

# Send the login to the server to authenticate
inner = {
    "sender": username,
    "recipient": None,
    "payload": {
        "password": password
    }
}

# Step 2: Encrypt and HMAC using session_key
plaintext = json.dumps(inner)
enc = encrypt_message(plaintext, session_key)
hmac_val = generate_hmac(json.dumps(enc), session_key)

# Step 3: Wrap it in the outer message with just the type
login_msg = json.dumps({
    "type": "AUTH",
    "enc": enc,
    "hmac": hmac_val
})
s.send(login_msg.encode())

resp = parse_message(s.recv(4096).decode())
if resp["type"] != "AUTH_RESP":
    print("Login failed:", resp["payload"])
    exit(1)

# Receive thread for handling messages from the server
def receive_loop(sock):
    while True:
        try:
            raw = sock.recv(4096).decode()
            msg = parse_message(raw)
            sender = msg["sender"]
            if msg["type"] == "KEY_EXCHANGE":
                # Generates reply DH keys
                privB, pubB, g, p = generate_dh_keypair()
                shared = compute_shared_secret(msg["payload"]["pubA"], privB, msg["payload"]["p"])
                key = derive_key(str(shared), salt=b"chat")
                session_keys[sender] = key

                # Send KEY_REPLY with pubB
                reply = build_message("KEY_REPLY", sender=username, recipient=sender, payload={"pubB": pubB})
                sock.send(reply.encode())

            elif msg["type"] == "KEY_REPLY":
                pubB = msg["payload"]["pubB"]
                pubA_data = incoming_dh.pop(sender)
                shared = compute_shared_secret(pubB, pubA_data["priv"], pubA_data["p"])
                key = derive_key(str(shared), salt=b"chat")
                session_keys[sender] = key
                print(f"[SECURE] Session with {sender} established.")

            elif msg["type"] == "MESSAGE":
                enc = msg["payload"]["enc"]
                hmac_val = msg["payload"]["hmac"]
                key = session_keys.get(sender)

                if not key or not verify_hmac(json.dumps(enc), hmac_val, key):
                    print(f"[SECURITY] Invalid message from {sender}")
                    continue

                plaintext = decrypt_message(enc, key)
                print(f"[{sender}]: {plaintext}")

            elif msg["type"] == "LIST":
                online_users = msg["payload"]
                print("[INFO] Online users:", online_users)

        except Exception as e:
            print("[ERROR]", e)
            break

# Log in message as well as sets up the thread for recieving responses from the server
print("Logged in as" + username)
threading.Thread(target=receive_loop, args=(s,), daemon=True).start()

# Communication loop dealing with user inputs for the commands: list, send, logout
while True:
    cmd = input("> ").strip()
    if cmd == "list":
        s.send(build_message("LIST", sender=username).encode())

    elif cmd == "logout":
        s.send(build_message("LOGOUT", sender=username).encode())
        print("Logged out.")
        s.close()
        session_keys.clear()
        break

    elif cmd.startswith("send "):
        parts = cmd.split(" ", 2)
        if len(parts) < 3:
            print("Usage: send USER MESSAGE")
            continue

        target, msg_text = parts[1], parts[2]

        # If no session key with target, initiate DH key exchange
        if target not in session_keys:
            print(f"[SECURE] No session key with {target}. Initiating key exchange...")
            priv, pub, g, p = generate_dh_keypair()

            payload = {
                "pubA": pub,
                "g": g,
                "p": p
            }

            s.send(build_message("KEY_EXCHANGE", sender=username, recipient=target, payload=payload).encode())

            # Store private key for when KEY_REPLY comes back
            incoming_dh[target] = {"priv": priv, "pub": pub, "p": p}
            print(f"Key exchange started with {target}. Please try sending again in a moment.")
            continue  # Skip this send for now

        # Encrypt + send secure message
        key = session_keys[target]
        enc = encrypt_message(msg_text, key)
        hmac_val = generate_hmac(json.dumps(enc), key)

        secure_payload = {
            "enc": enc,
            "hmac": hmac_val
        }

        message = build_message("MESSAGE", sender=username, recipient=target, payload=secure_payload)
        s.send(message.encode())
    

    else:
        print("Unknown command")



