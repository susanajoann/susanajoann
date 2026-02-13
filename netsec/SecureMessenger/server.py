import configparser
import socket
import threading
import json
import time
import os
from protocol import *
from base64 import b64decode
from crypto_tools import derive_key

USERS_FILE = "users.json"

clients = {} # username -> [conn, addr]
login_attempts = {}  # username -> [timestamp1, timestamp2, etc]
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 60

# Implementation to handle a client with a connection and a specific address
def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    try:
        # Receive login message
        raw = conn.recv(4096).decode()
        msg = parse_message(raw)
        username = msg["sender"]
        password = msg["payload"]["password"]

        # Loads a user verifier and salt
        with open(USERS_FILE) as f:
            users = json.load(f)

        if username not in users:
            salt = os.urandom(16)
            key =  derive_key(password, salt)
            user_data = {
                    "salt": b64decode(salt).decode(),
                    "verifier": b64decode(key).decode()
                    }
            db  = {username: user_data}
            with open("users.json", "w") as f:
                json.dump(db, f, indent=2)
            print("created user" + username)
        
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