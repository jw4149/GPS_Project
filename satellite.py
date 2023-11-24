import socket
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

session = 0

def send_data(key):
    global session
    sndr_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sndr_socket.connect((socket.gethostname(), 12346))
    
    try:
        while True:
            session += 1
            print("Entered session: ", session)
            data = input("Enter nav data to send: ")
            hm = hmac.HMAC(key, hashes.SHA256())
            hm.update(data.encode('utf-8'))
            mac = hm.finalize().hex()
            sndr_socket.send((data+":"+mac).encode('utf-8'))
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
    key = kdf.derive(b"gps authentication key")
    send_data(key)
