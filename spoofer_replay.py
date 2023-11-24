import socket
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

session = 0

def send_data():
    global session
    sndr_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sndr_socket.connect((socket.gethostname(), 12347))
    
    try:
        while True:
            session += 1
            print("Entered session: ", session)
            data = input("Enter nav data to send: ")
            key_str = input("Enter key to send: ")
            key = bytes.fromhex(key_str)
            hm = hmac.HMAC(key, hashes.SHA256())
            hm.update(data.encode('utf-8'))
            mac = hm.finalize().hex()
            sndr_socket.send((key_str+":"+data+":"+mac).encode('utf-8'))
            print("Session", session, "finished.")
    finally:
        sndr_socket.close()

if __name__ == '__main__':
    send_data()