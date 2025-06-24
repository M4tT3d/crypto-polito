# posso sfruttare la propietà moltiplicativa della cifratura RSA
# r = 2, c = (m^e mod n)
# c' = (r^e mod n) * (m^e mod n) = (c * r^e mod n)
# dec(c') = (m * r) mod n. Calcolando l'inverso di r modulo n ottengo
# m = (dec(c') * r^-1) mod n
# il problema in questa ctf è che il server non mi restituisce il valore di n,
# ma solo il valore di c.
# per ricare n posso sfruttare il fatto che il server mi permette di cifrare
# dei dati a piacimento (2 e 3 in questo caso).
# calcolo c1 = encrypt(2) e c2 = encrypt(3)
# calcolo n = gcd(c1 - 2^e, c2 - 3^e).
# Funziona perchè (2^e - c1) e (3^e - c2) sono multipli di n.

import os

os.environ["PWNLIB_NOTERM"] = "True"
from pwn import remote
from Crypto.Util.number import long_to_bytes, inverse
from gmpy2.gmpy2 import gcd

server = remote("130.192.5.212", 6646)
e = 65537

chiphertext = int(server.recvline().decode().strip())
print(chiphertext)
server.sendline("e2".encode())
c2 = int(server.recvline().decode().strip())
server.sendline("e3".encode())
c3 = int(server.recvline().decode().strip())
n = gcd((pow(2, e) - c2), (pow(3, e) - c3))
s = 2
c_blind = (chiphertext * pow(s, e, n)) % n
server.sendline(f"d{c_blind}".encode())
m_blind = int(server.recvline().decode().strip())
m = (m_blind * inverse(s, n)) % n
print(long_to_bytes(m))
