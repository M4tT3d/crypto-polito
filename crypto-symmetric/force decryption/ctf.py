import os
os.environ["PWNLIB_NOTERM"] = "True"
import pwn
from Crypto.Util.strxor import strxor

server = pwn.connect("130.192.5.212", 6523)
pwn.context(log_level="debug", terminal=None)
server.timeout = 2
leak = b"mynamesuperadmin"

print(server.recvline_contains(b"again", keepends=True))
print(server.recv(1024))
server.sendline(b"enc")
print(server.recvline().decode())
plaintext = b"a"*16
server.sendline(plaintext.hex().encode())
iv = bytes.fromhex(server.recvline().decode().split(":")[1].strip())
print(iv)
chipertext = bytes.fromhex(server.recvline().decode().split(":")[1].strip())
print(chipertext)
iv_forged = strxor(iv, strxor(plaintext, leak))
print(iv_forged)
print(server.recvline_contains(b"again", keepends=True))
print(server.recv(1024))
server.sendline(b"dec")
print(server.recvline_contains(b"decrypt", keepends=True))
print(server.recv(1024))
server.sendline(chipertext.hex().encode())
print(server.recvline_contains(b"IV", keepends=True))
print(server.recv(1024))
server.sendline(iv_forged.hex().encode())
print(server.recv(1024 * 10).decode())
