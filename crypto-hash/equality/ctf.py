import os

os.environ["PWNLIB_NOTERM"] = "True"
from pwn import remote

# stringhe prese dalla lezione del professore perchè non sono riuscito a
# a far girare lo script che implementa la collisione su MD4
server = remote("130.192.5.212", 6631)

print(server.recvline().decode().strip())
server.sendline(
    "f4bf625ccd653c06b556939f5e1c2841565ce6c2d17f38dfd96b2620891dfeaa2de86cdef84fd9f5415ad71307af279fc473e988ae5405d3aa064540f33d35a1".encode()
)
server.sendline(
    "f4bf625ccd653c86b556930f5e1c2841565ce6c2d17f38dfd96b2620891dfeaa2de86cdef84fd9f5415ad71307af279fc473e888ae5405d3aa064540f33d35a1".encode()
)
print(server.recvline().decode().strip())
