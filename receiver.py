import socket
import threading
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidSignature

session = 0

def handle_sndr(sndr_sk, addr, key):
    global session
    try:
        while True:
            data = sndr_sk.recv(1024)
            session += 1
            print("Entered session: ", session)

            msgs = data.decode('utf-8').split(":")
            msg = msgs[0]
            mac = bytes.fromhex(msgs[1])

            hm = hmac.HMAC(key, hashes.SHA256())
            hm.update(msg.encode())
            try:
                hm.verify(mac)
                print("Message authenticated. Received message is:", msg)
                print("Session", session, "finished.")
            except InvalidSignature:
                print("MAC is not valid. Messaged is spoofed.")
                session -= 1
                print("Downgraded session to id", session, "to sync with gps.")

            if not data:
                break
            # print(f"Received from {addr}: {data.decode('utf-8')}")
    finally:
        sndr_sk.close()

def receive_data(key):
    rcv_sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    rcv_sk.bind((socket.gethostname(), 12346))
    rcv_sk.listen(5)

    print("Receiver ready.")

    while True:
        sndr_sk, addr = rcv_sk.accept()
        sndr_thread = threading.Thread(target=handle_sndr, args=(sndr_sk, addr, key))
        sndr_thread.start()

if __name__ == '__main__':
    salt = b'1'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = kdf.derive(b"gps authentication key")
    receive_data(key)        