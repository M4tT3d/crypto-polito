import os
os.environ["PWNLIB_NOTERM"] = "True"
from pwn import remote
from Crypto.Util.number import long_to_bytes, inverse

server = remote("130.192.5.212", 6645)
e = 65537

n = int(server.recvline().decode().strip())
print(n)
chiphertext = int(server.recvline().decode().strip())
print(chiphertext)
s = 2
c_blind = (chiphertext * pow(s, e, n)) % n
server.sendline(f"d{c_blind}".encode())
m_blind = int(server.recvline().decode().strip())
m = (m_blind * inverse(s, n)) % n
print(long_to_bytes(m))