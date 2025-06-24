import pwn
from Crypto.Util.strxor import strxor

server = pwn.connect("130.192.5.212", 6531)
server.timeout = 2
for i in range(128):
    print(server.recvline().decode())
    msg = server.recvline().decode()
    print(msg)
    print(server.recvline().decode())
    if i == 0:
        otp = bytes.fromhex(msg.split(":")[1].strip())
    else:
        otp = bytes.fromhex(msg.split("\n")[4].split(":")[1].strip())
    input_data = b"A" * 32
    server.sendline(strxor(input_data, otp).hex().encode())
    cipher = server.recv(1024).decode().split(":")[1].split("\n")[0].strip()
    cipher_bytes = bytes.fromhex(cipher)
    mode = b"ECB" if cipher_bytes[:16] == cipher_bytes[16:32] else b"CBC"
    server.sendline(mode)
    # msg = server.recv(1024).decode()
print(server.recv(1024).decode())
server.close()