from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
# from secret import flag
import json
import base64
import socket
flag = "EEEEEEEE"

key = get_random_bytes(32)


def get_user_token(name):
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    token = json.dumps({
        "username": name,
        "admin": False
    })
    enc_token = cipher.encrypt(pad(token.encode(), AES.block_size))
    return f"{base64.b64encode(enc_token).decode()}"


def check_user_token(token):
    cipher = AES.new(key=key, mode=AES.MODE_ECB) 
    test = cipher.decrypt(base64.b64decode(token))
    dec_token = unpad(test, AES.block_size)

    user = json.loads(dec_token)

    if user.get("admin", False) == True:
        return True
    else:
        return False


def get_flag():
    token = input("What is your token?\n> ").strip()
    if check_user_token(token):
        print("You are admin!")
        print(f"This is your flag!\n{flag}")
    else:
        print("HEY! WHAT ARE YOU DOING!?")
        exit(1)


def handle_client(conn):
    conn.sendall(b"Hi, please tell me your name!\n> ")
    name = recv_line(conn).strip()
    token = get_user_token(name)
    conn.sendall(f"This is your token: {token}\n".encode())

    menu = (
        "What do you want to do?\n"
        "quit - quit the program\n"
        "help - show this menu again\n"
        "flag - get the flag\n"
        "> "
    )

    while True:
        conn.sendall(menu.encode())
        cmd = recv_line(conn).strip()

        if cmd == "quit":
            break
        elif cmd == "help":
            continue
        elif cmd == "flag":
            conn.sendall(b"What is your token?\n> ")
            token = recv_line(conn).strip()
            if check_user_token(token):
                conn.sendall(b"You are admin!\n")
                conn.sendall(f"This is your flag!\n{flag}\n".encode())
            else:
                conn.sendall(b"HEY! WHAT ARE YOU DOING!?\n")
                break
        else:
            conn.sendall(b"Unknown command\n")

    conn.close()


def recv_line(conn):
    line = b""
    while not line.endswith(b"\n"):
        data = conn.recv(1)
        if not data:
            break
        line += data
    return line.decode()


def main():
    HOST = "0.0.0.0"
    PORT = 1338

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"Server listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            print(f"Connected by {addr}")
            handle_client(conn)


if __name__ == "__main__":
    main()
