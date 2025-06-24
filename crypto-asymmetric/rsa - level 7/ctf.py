import os
os.environ['PWNLIB_NOTERM'] = 'True'
from pwn import remote
from Crypto.Util.number import long_to_bytes

server = remote("130.192.5.212", 6647)
server.log(2, "DEBUG")
n = int(server.recvline(keepends=False))
chiphertext = int(server.recvline(keepends=False))
# server.close()
e = 65537
# attack LSB oracle
upper_bond = n
lower_bond = 0
m = chiphertext

for i in range(n.bit_length()):
    m = (pow(2, e, n) * m) % n
    # server = remote("130.192.5.212", 6647)
    server.sendline(str(m).encode())
    bit = server.recvline(keepends=False).decode()
    # server.close()
    if int(bit[0]) == 1:
        lower_bond = (lower_bond + upper_bond) // 2
    else:
        upper_bond = (lower_bond + upper_bond) // 2
    print(f"lower_bond: {lower_bond}, upper_bond: {upper_bond}")

print(lower_bond)
print(f"FLAG: ${long_to_bytes(upper_bond)}")