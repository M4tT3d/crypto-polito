import pwn
from Crypto.Util.strxor import strxor
import base64
import json

def main():
    username = "hackerino"
    server = pwn.connect("130.192.5.212", 6521)
    server.recv(1024)
    server.sendline(username.encode())
    server.recv(1024)
    msg = server.recv(1024)
    cipher_token = msg.decode().split('\n')[0].split(":")[1].strip()
    print("TOKEN", cipher_token)
    nonce, token = cipher_token.split(".")
    print("BOTH encoded in base64")
    print("NONCE", nonce, " TOKEN ", token)
    token_bytes = bytes.fromhex(base64.b64decode(token).hex())
    keystream = strxor(token_bytes, json.dumps({"username": username}).encode())
    print("KEYSTREAM", keystream.hex())
    payload = strxor(keystream, json.dumps({"us": "", "admin": True}).encode())
    server.sendline(b"flag")
    print(server.recv(1024))
    server.sendline(f"{nonce}.{base64.b64encode(payload).decode()}".encode())
    flag = server.recv(1024).decode().split("\n")[2]
    print("FLAG", flag)
    server.close()

if __name__ == "__main__":
    main()