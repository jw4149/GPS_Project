import socket
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# session = 0
key_chain = []

def send_data():
    global session
    sndr_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sndr_socket.connect((socket.gethostname(), 12347))
    
    try:
        for session in range(1, 6):
            key_auth = key_chain[session]
            key_send = key_chain[session-1].hex()
            print("Entered session: ", session)
            data = input("Enter nav data to send: ")
            hm = hmac.HMAC(key_auth, hashes.SHA256())
            hm.update(data.encode('utf-8'))
            mac = hm.finalize().hex()
            sndr_socket.send((key_send+":"+data+":"+mac).encode('utf-8'))
            print("Key sent in session", session, "is", key_send)
            print("Just info: Message", data, "can only be authenticated with key", key_auth.hex())
            print("Session", session, "finished.")
    finally:
        sndr_socket.close()

if __name__ == '__main__':
    salt = b'1'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key_N = kdf.derive(b"gps authentication key")
    key_chain.append(key_N)

    digest = hashes.Hash(hashes.SHA256())
    key = key_N
    for i in range(5):
        digest.update(key)
        key = digest.finalize()
        key_chain.insert(0, key)
        digest = hashes.Hash(hashes.SHA256())

    send_data()
