import pwn
from Crypto.Util.strxor import strxor

#dal momento che viene utilizzato sempre lo stesso otp per cifrare i dati, 
# possiamo capire quale metodo di cifratura viene utilizzato in base al risultato.
# se i due ciphertext sono uguali, allora il metodo di cifratura è ECB, altrimenti CBC

server = pwn.connect("130.192.5.212", 6532)
server.timeout = 2
for _ in range(128):
    print(server.recvline().decode())
    plaintext = "a"*64
    server.sendline(plaintext.encode())
    msg = server.recvline().decode()
    print(msg)
    ciphertext1 = msg.split(":")[2].strip()
    print(ciphertext1)
    print(server.recvline().decode())
    server.sendline(plaintext.encode())
    msg = server.recvline().decode()
    print(msg)
    ciphertext2 = msg.split(":")[2].strip()
    print(ciphertext2)
    print(server.recvline().decode())
    mode = "ECB" if ciphertext1 == ciphertext2 else "CBC"
    server.sendline(mode.encode())
    print(server.recvline().decode())
print(server.recvline().decode())
