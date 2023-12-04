import socket
import threading
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidSignature

session = 0
prev_msg = None
prev_key = None
prev_mac = None

def handle_sndr(sndr_sk, addr):
    global session, prev_msg, prev_key, prev_mac
    try:
        while True:
            data = sndr_sk.recv(1024)
            session += 1
            print("Entered session: ", session)

            msgs = data.decode('utf-8').split(";")
            key = bytes.fromhex(msgs[0])
            msg = msgs[1]
            mac = bytes.fromhex(msgs[2])
            print("Received message", msg, "will be verified in next session.")

            if session == 1:
                # No verification to do
                prev_msg = msg
                prev_key = key
                prev_mac = mac
                print("Session", session, "finished.")
            else:
                # Verify the prev_msg with received key
                hm = hmac.HMAC(key, hashes.SHA256())
                hm.update(prev_msg.encode())
                try:
                    hm.verify(prev_mac)
                    print("Message received in session", session-1, prev_msg, "is authenticated.")
                    prev_msg = msg
                    prev_key = key
                    prev_mac = mac
                    print("Session", session, "finished.")
                except InvalidSignature:
                    print("MAC is not valid. Messaged is spoofed.")
                    print("Received message", msg, "is discarded.")
                    session -= 1
                    print("Downgraded session to id", session, "to sync with gps.")

            if not data:
                break
            
    finally:
        sndr_sk.close()

def receive_data():
    rcv_sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    rcv_sk.bind((socket.gethostname(), 12347))
    rcv_sk.listen(5)

    print("Receiver ready.")

    while True:
        sndr_sk, addr = rcv_sk.accept()
        sndr_thread = threading.Thread(target=handle_sndr, args=(sndr_sk, addr))
        sndr_thread.start()

if __name__ == '__main__':
    receive_data()        