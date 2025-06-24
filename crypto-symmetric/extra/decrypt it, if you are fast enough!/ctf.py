import os
os.environ["PWNLIB_NOTERM"] = "True"
from pwn import remote
from time import time
from Crypto.Util.strxor import strxor

server = remote("130.192.5.212", 6562)

print(server.recv(1024))
server.sendline(b"f")
flag = bytes.fromhex(server.recvline().decode().strip())
print(f"Flag ct: {flag.hex()}")
server.sendline(b"y")
plaintext = b"a" * len(flag)
print(f"Plaintext: {plaintext.hex()}")
server.sendline(plaintext)
know_ct = bytes.fromhex(server.recvline().decode().split(">")[1].strip())
print(f"Known Ciphertext: {know_ct.hex()}")
keystream = strxor(plaintext, know_ct)
print(f"Keystream: {keystream.hex()}")
print(f"Flag: {strxor(flag, keystream).decode()}")