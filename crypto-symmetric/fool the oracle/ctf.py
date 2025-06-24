import pwn
from Crypto.Cipher import AES
import string

server = pwn.remote("130.192.5.212", 6541)
server.timeout = 2

def split_blocks(data: str, block_size=AES.block_size):
    return [data[i : i + 2*block_size] for i in range(0, len(data), 2*block_size)]

flag = b"CRYPTO25{96ce8a9"
while len(flag) < 46:
    print(server.recvline_contains(b"again").decode())
    server.sendlineafter(b"> ", b"enc")
    len_payload = AES.block_size - (len(flag) % AES.block_size) - 1
    payload = b"A" * len_payload
    server.sendline(payload.hex().encode())
    chipertext = server.recvline().decode().split(">")[1].strip()
    chiper_blocks = split_blocks(chipertext)
    target_block = chiper_blocks[len(flag) // AES.block_size]

    guess_ok = False
    for guess_byte in string.printable.encode():
        server.recvline_contains(b"again").decode()
        to_send = payload + flag + bytes([guess_byte])
        server.sendlineafter(b"> ", b"enc")
        server.sendline(to_send.hex().encode())
        chipertext = server.recvline().decode().split(">")[1].strip()
        chiper_blocks = split_blocks(chipertext)
        test_block = chiper_blocks[len(flag) // AES.block_size]
        if test_block == target_block:
            flag += bytes([guess_byte])
            print("FLAG: " + flag.decode())
            guess_ok = True
            break
    if not guess_ok:
        print("Guess failed")
        break
