import json

# Message types
LIST_REQUEST = "LIST" # List type of message for client functionality
AUTH_REQUEST = "AUTH" # Authentication message to authenticate users
AUTH_RESPONSE = "AUTH_RESP" # Authentication Response to authentication request
MESSAGE = "MESSAGE" # A normal Message with text to another user
KEY_EXCHANGE = "KEY_EXCHANGE" # Key exchange message between users
KEY_REPLY = "KEY_REPLY" # A key reply message
ERROR = "ERROR" # An error message indicating failure
LOGOUT_REQUEST = "LOGOUT" # Request to logout of the server and close connection

# Sends a JSON formatted message
def build_message(msg_type, sender=None, recipient=None, payload=None, hmac_val=None):
    return json.dumps({
        "type": msg_type,
        "sender": sender,
        "recipient": recipient,
        "payload": payload,
        "hmac": hmac_val
    })

# Parses a given string into a JSON formatted message
def parse_message(msg_str):
    return json.loads(msg_str)

# Helper for printing debug messages
def print_message(msg_json):
    print(json.dumps(parse_message(msg_json), indent=2))