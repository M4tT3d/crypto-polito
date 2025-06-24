import os

os.environ["PWNLIB_NOTERM"] = "TRUE"
import string
from Crypto.Cipher import AES
from pwn import remote

BLOCK_SIZE = AES.block_size
MAX_LEN_FLAG = 46


def split_blocks(data: str, block_size=BLOCK_SIZE):
    ct = bytes.fromhex(data)
    return [ct[i : i + block_size] for i in range(0, len(ct), block_size)]


server = remote("130.192.5.212", 6542)
server.timeout = 2
flag = b""
padding_len = 5
while len(flag) < MAX_LEN_FLAG:
    print(server.recvline_contains(b"again"))
    server.sendlineafter(b"> ", b"enc")
    len_payload = BLOCK_SIZE - (len(flag) % BLOCK_SIZE) - 1
    payload = b"b" * (BLOCK_SIZE - padding_len) + b"a" * len_payload
    server.sendline(payload.hex().encode())
    chiphertext = server.recvline().decode().split(">")[1].strip()
    chiperblocks = split_blocks(chiphertext)
    target_block = chiperblocks[(len(flag) // BLOCK_SIZE) + 1]

    guess_ok = False
    for guess_byte in string.printable.encode():
        server.recvline_contains(b"again")
        to_send = payload + flag + bytes([guess_byte])
        server.sendlineafter(b"> ", b"enc")
        server.sendline(to_send.hex().encode())
        chiphertext = server.recvline().decode().split(">")[1].strip()
        chiperblocks = split_blocks(chiphertext)
        test_blcock = chiperblocks[(len(flag) // BLOCK_SIZE) + 1]
        if test_blcock == target_block:
            flag += bytes([guess_byte])
            print(f"Found byte: {guess_byte} -> {flag}")
            guess_ok = True
            break
    if not guess_ok:
        print("No more guesses found, exiting...")
        break
