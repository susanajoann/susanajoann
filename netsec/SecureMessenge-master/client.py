import socket
import json
import time
from protocol import *
from crypto_tools import *
import getpass
import configparser
import threading
from threading import Event

# Reads the config to connect to
config = configparser.ConfigParser()
config.read("config.ini")
host = config["server"]["host"]
port = int(config["server"]["port"])

MAX_RETRIES = 3
session_keys = {}
offline_users = {}
incoming_dh = {}

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))

# Run DH key exchange
privA, pubA, g, p = generate_dh_keypair()
key_exchange_msg = build_message("KEY_EXCHANGE", sender="preauth", payload={"pubA": pubA, "g": g, "p": p})
s.send(key_exchange_msg.encode())

try:
    raw = s.recv(4096).decode()
    msg = parse_message(raw)
    pubB = msg["payload"]["pubB"]
    shared_secret = compute_shared_secret(pubB, privA, p)
    session_key = derive_key(str(shared_secret), salt=b"prelogin")
    session_keys["server"] = session_key
except Exception as e:
    print("Failed key exchange:", e)
    s.close()
    exit(1)

for attempt in range(MAX_RETRIES):
    # Prompt login
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    inner = {
        "sender": username,
        "recipient": None,
        "payload": {"password": password}
    }

    plaintext = json.dumps(inner)
    enc = encrypt_message(plaintext, session_keys["server"])
    hmac_val = generate_hmac(json.dumps(enc), session_keys["server"])

    login_msg = json.dumps({
        "type": "AUTH",
        "enc": enc,
        "hmac": hmac_val
    })

    try:
        s.send(login_msg.encode())
        resp = parse_message(s.recv(4096).decode())
        if resp["type"] == "AUTH_RESP":
            break  # Success
        else:
            print("Login failed:", resp["payload"])
    except Exception as e:
        print("Login failed (server error):", e)

    if attempt == MAX_RETRIES - 1:
        print("Too many failed login attempts. Exiting.")
        s.close()
        exit(1)

# Reciever loop for a client when it recieves responses from either another client or responses from the server about info of the network
def receive_loop(sock):
    while True:
        try:
            raw = sock.recv(4096).decode()
            msg = parse_message(raw)
            sender = msg["sender"]

            if msg["type"] == "KEY_EXCHANGE":
                privB, pubB, g, p = generate_dh_keypair()
                shared = compute_shared_secret(msg["payload"]["pubA"], privB, msg["payload"]["p"])
                key = derive_key(str(shared), salt=b"chat")
                session_keys[sender] = key
                reply = build_message("KEY_REPLY", sender=username, recipient=sender, payload={"pubB": pubB})
                sock.send(reply.encode())

            elif msg["type"] == "KEY_REPLY":
                pubB = msg["payload"]["pubB"]
                pubA_data = incoming_dh.pop(sender)
                shared = compute_shared_secret(pubB, pubA_data["priv"], pubA_data["p"])
                key = derive_key(str(shared), salt=b"chat")
                session_keys[sender] = key

            elif msg["type"] == "MESSAGE":
                enc = msg["payload"]["enc"]
                hmac_val = msg["payload"]["hmac"]
                key = session_keys.get(sender)
                if not key or not verify_hmac(json.dumps(enc), hmac_val, key):
                    print(f"SECURITY: Invalid message from {sender}")
                    continue
                plaintext = decrypt_message(enc, key)
                print(f"[{sender}]: {plaintext}")
                print("> ", end="", flush=True)

            elif msg["type"] in ["LIST", "AUTH_RESP", "ERROR"]:
                enc = msg["enc"]
                hmac_val = msg["hmac"]
                key = session_keys.get("server")
                if not key or not verify_hmac(json.dumps(enc), hmac_val, key):
                    print(f"SECURITY: Invalid {msg['type']} message from server")
                    continue
                plaintext = decrypt_message(enc, key)
                if msg["type"] == "LIST":
                    print("INFO: Online users:", json.loads(plaintext))
                
                elif "Recipient offline" in plaintext:
                    for target in incoming_dh:
                        offline_users[target] = True
                    print(f"ERROR: {plaintext}")
                else:
                    print(f"[{msg['type']}] {plaintext}")

        except OSError:
            break
        except Exception as e:
            print("ERROR:", e)
            break

# Log in message as well as sets up the thread for recieving responses from the server
print("Logged in as " + username)
threading.Thread(target=receive_loop, args=(s,), daemon=True).start()

# Communication loop dealing with user inputs for the commands: list, send, logout
while True:
    cmd_raw = input("> ").strip()
    cmd_parts = cmd_raw.split(" ", 1)
    cmd = cmd_parts[0].lower()
    rest = cmd_parts[1] if len(cmd_parts) > 1 else ""

    if cmd == "list":
        key = session_keys.get("server")
        if not key:
            print("ERROR: No session key with server.")
            continue
        enc = encrypt_message("LIST", key)
        hmac_val = generate_hmac(json.dumps(enc), key)
        s.send(json.dumps({
            "type": "LIST",
            "sender": username,
            "enc": enc,
            "hmac": hmac_val
        }).encode())

    elif cmd == "logout":
        s.send(build_message("LOGOUT", sender=username).encode())
        print("Logging off as " + username + " from " + host)
        session_keys.clear()
        try:
            s.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        s.close()
        break

    elif cmd == "send":
        send_parts = rest.split(" ", 1)
        if len(send_parts) < 2:
            print("Usage: send USER MESSAGE")
            continue

        target, msg_text = send_parts[0], send_parts[1]

        if target not in session_keys:
            # Start DH key exchange
            priv, pub, g, p = generate_dh_keypair()
            payload = {"pubA": pub, "g": g, "p": p}
            s.send(build_message("KEY_EXCHANGE", sender=username, recipient=target, payload=payload).encode())
            incoming_dh[target] = {"priv": priv, "pub": pub, "p": p}

            # Wait for either session key or offline error
            start = time.time()
            while target not in session_keys and target not in offline_users:
                if time.time() - start > 5:
                    print(f"TIMEOUT: Failed to establish session with {target}")
                    break
                time.sleep(0.1)

            # Handle offline or timeout
            if target in offline_users:
                offline_users.pop(target)
                continue

            if target not in session_keys:
                continue  # Skip send if key wasn't established

        # Encrypt and send secure message
        key = session_keys[target]
        enc = encrypt_message(msg_text, key)
        hmac_val = generate_hmac(json.dumps(enc), key)
        message = build_message("MESSAGE", sender=username, recipient=target, payload={
            "enc": enc,
            "hmac": hmac_val
        })
        s.send(message.encode())

    else:
        print("Unknown command")



