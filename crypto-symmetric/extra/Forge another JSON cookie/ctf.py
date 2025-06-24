import os

os.environ["PWNLIB_NOTERM"] = "True"
from pwn import remote
import json
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def get_blocks(b64token):
    token = base64.b64decode(b64token)
    return [token[i : i + AES.block_size] for i in range(0, len(token), AES.block_size)]


# server = remote("0.0.0.0", 1338)
server = remote("130.192.5.212", 6551)
payload = (
    "a" * 2
    + " " * 7
    + "  : true,"
    + " " * 15
    + '"'
    + " " * 17
    + "test"
    + " " * 15
    + ","
)
print(server.recvline())
server.sendline(payload.encode())
token = server.recvline().decode().split(": ")[1].strip()
json_to_enc = pad(
    json.dumps({"username": payload, "admin": False}).encode(), AES.block_size
)
print(json.dumps({"username": payload, "admin": False}))
blocks = get_blocks(token)
blocks_j = [
    json_to_enc[i : i + AES.block_size]
    for i in range(0, len(json_to_enc), AES.block_size)
]
for i, blk in enumerate(blocks):
    print(f"Block {i}: {blk.hex()}")
for i, blk in enumerate(blocks_j):
    print(f"Block_j {i}: {blk}")
print(server.recvuntil(b"flag"))
print(server.recv(1024))
server.sendline(b"flag")
print(server.recvline())
server.sendline(
    base64.b64encode(
        blocks[0]
        + blocks[5]
        + blocks[1]
        + blocks[3]
        + blocks[4]
        + blocks[3]
        + blocks[6]
    )
)
print(server.recvline())
print(server.recvall())
