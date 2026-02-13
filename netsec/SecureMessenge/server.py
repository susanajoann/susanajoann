import configparser
import socket
import threading
import json
import time
import os
from protocol import *
from base64 import b64decode, b64encode
from crypto_tools import *

USERS_FILE = "users.json"

clients = {} # username -> [conn, addr]
login_attempts = {}  # username -> [timestamp1, timestamp2, etc]
temp_sessions = {}  # conn -> session_key
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 60

# Implementation to handle a client with a connection and a specific address
def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    try:
        # Step 1: Wait for KEY_EXCHANGE message from client
        raw = conn.recv(4096).decode()
        msg = parse_message(raw)

        if msg["type"] != "KEY_EXCHANGE":
            conn.send(build_message("ERROR", payload="Expected key exchange").encode())
            conn.close()
            return

        pubA = msg["payload"]["pubA"]
        g = msg["payload"]["g"]
        p = msg["payload"]["p"]

        privB, pubB, _, _ = generate_dh_keypair()
        shared_secret = compute_shared_secret(pubA, privB, p)
        session_key = derive_key(str(shared_secret), salt=b"prelogin")
        temp_sessions[conn] = session_key

        # Send back pubB to client
        reply = build_message("KEY_REPLY", sender="server", payload={"pubB": pubB})
        conn.send(reply.encode())

        raw = conn.recv(4096).decode()
        msg = parse_message(raw)

        if msg["type"] != "AUTH":
            conn.send(build_message("ERROR", payload="Expected AUTH").encode())
            conn.close()
            return

        enc = msg["enc"]
        hmac_val = msg["hmac"]

        if not verify_hmac(json.dumps(enc), hmac_val, session_key):
            conn.send(build_message("ERROR", payload="HMAC verification failed").encode())
            return

        decrypted = decrypt_message(enc, session_key)
        inner = json.loads(decrypted)

        username = inner["sender"]
        password = inner["payload"]["password"]

        if not os.path.exists(USERS_FILE) or os.path.getsize(USERS_FILE) == 0:
            users = {}
            with open(USERS_FILE, "w") as f:
                json.dump(users, f)
        else:
            with open(USERS_FILE, "r") as f:
                users = json.load(f)

        if username not in users:
            salt = os.urandom(16)
            key = derive_key(password, salt)
            user_data = {
                "salt": b64encode(salt).decode(),
                "verifier": b64encode(key).decode()
            }
            users[username] = user_data
            with open(USERS_FILE, "w") as f:
                json.dump(users, f, indent=2)
            print("created user " + username)

        salt = b64decode(users[username]["salt"])
        verifier = b64decode(users[username]["verifier"])
        derived = derive_key(password, salt)

        if derived != verifier:
            conn.send(build_message("ERROR", payload="Incorrect password").encode())
            now = time.time()
            attempts = login_attempts.get(username, [])
            attempts = [t for t in attempts if now - t < WINDOW_SECONDS]
            if len(attempts) >= MAX_ATTEMPTS:
                conn.send(build_message("ERROR", payload="Too many login attempts. Try again later.").encode())
                return
            attempts.append(now)
            login_attempts[username] = attempts
            return

        clients[username] = (conn, addr)
        conn.send(build_message("AUTH_RESP", payload="OK").encode())

        # Step 3: Handle commands
        while True:
            raw = conn.recv(4096).decode()
            msg = parse_message(raw)

            if msg["type"] == "LIST":
                online = list(clients.keys())
                conn.send(build_message("LIST", payload=online).encode())

            elif msg["type"] == "MESSAGE":
                recipient = msg["recipient"]
                if recipient in clients:
                    target_conn, _ = clients[recipient]
                    target_conn.send(raw.encode())
                else:
                    conn.send(build_message("ERROR", payload="Recipient offline").encode())

            elif msg["type"] == "KEY_EXCHANGE":
                recipient = msg["recipient"]
                if recipient in clients:
                    target_conn, _ = clients[recipient]
                    target_conn.send(raw.encode())
                else:
                    conn.send(build_message("ERROR", payload="Recipient offline").encode())

            elif msg["type"] == "KEY_REPLY":
                recipient = msg["recipient"]
                if recipient in clients:
                    target_conn, _ = clients[recipient]
                    target_conn.send(raw.encode())
                else:
                    conn.send(build_message("ERROR", payload="Recipient offline").encode())

            elif msg["type"] == "LOGOUT":
                print(f"[LOGOUT] {username} from {addr}")
                conn.send(build_message("AUTH_RESP", payload="Logged out.").encode())
                break

    except Exception as e:
        print("Client error:", e)
    finally:
        conn.close()
        for user, (c, _) in clients.items():
            if c == conn:
                del clients[user]
                print(f"[DISCONNECTED] {addr} ({user})")
                break

# Starts the server and begins to handle connections from clients
def start_server(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(5)
    print(f"[SERVER STARTED] Listening on {host}:{port}")

    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

# Setting up the IP and Port the server should bind to from the config.ini file
if __name__ == "__main__":
    config = configparser.ConfigParser()
    config.read("config.ini")

    host = config["server"]["host"]
    port = int(config["server"]["port"])

    start_server(host, port)
