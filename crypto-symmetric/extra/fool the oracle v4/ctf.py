import os

os.environ["PWNLIB_NOTERM"] = "TRUE"
import string
from Crypto.Cipher import AES
from pwn import remote

BLOCK_SIZE = AES.block_size
MAX_FLAG_LEN = 46
MAX_PREFIX_LEN = 6
MIN_PREFIX_LEN = 1
ENABLE_SUFFIX = True
server = remote("130.192.5.212", 6543)
# server = remote("0.0.0.0", 6543)
server.timeout = 2


def split_blocks(data: str, block_size=BLOCK_SIZE):
    ct = bytes.fromhex(data)
    return [ct[i : i + block_size] for i in range(0, len(ct), block_size)]


def get_padding_len():
    for i in range(BLOCK_SIZE - MAX_PREFIX_LEN, BLOCK_SIZE):
        payload = b"A" * i + b"B" * BLOCK_SIZE * 2
        server.sendlineafter(b"> ", b"enc")
        server.sendline(payload.hex().encode())
        ciphertext = server.recvline().decode().split(">")[1].strip()
        ct_blocks = split_blocks(ciphertext)
        for j in range(len(ct_blocks) - 1):
            if ct_blocks[j] == ct_blocks[j + 1]:
                padding1_len = (BLOCK_SIZE - i) % BLOCK_SIZE
                print(f"Trovata lunghezza di prefix: {padding1_len}")
                return padding1_len
    print("Impossibile determinare la lunghezza di prefix.")
    return None


# for i in range(1, MAX_PADDING_LEN + 1):
padding_len = get_padding_len()
if padding_len is None:
    print("Exiting due to inability to determine padding length.")
    exit(1)
flag = b""
while len(flag) < MAX_FLAG_LEN:
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
    if len(flag) == MAX_FLAG_LEN:
        break
