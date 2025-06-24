# il problema di questo server è che riutilizza lo stesso nonce per cifrare
# più messaggi. Questa pratica è risaputa essere vulnerabile a un attacco di 
# tipo keystream reuse attack. Infatti è possibile calcolare il keystream
# usato per cifrare il messaggio partendo da un plaintext noto all'attaccante

import pwn
from Crypto.Util.strxor import strxor

server = pwn.remote("130.192.5.212", 6561)
# pwn tool preferisce inviare bytes ma supporta anche le stringhe

msg = server.recv(1024)
print(msg)
server.sendline(b"1234")
flag = server.recv(1024)
# ricevo altri dati oltre al flag cifrato. Quindi decodifico il messaggio
# e lo divido in base al carattere di newline e prendo solo il primo elemento
flag = server.recv(1024).decode().split("\n")[0]
# il flag è in esadecimale quindi lo converto in bytes
flag = bytes.fromhex(flag)
print("LEN FLAG", len(flag))
server.sendline(b"y")
msg = server.recv(1024)
print(msg)
# genero un plaintext di test lungo quanto il flag
test_str = b"A"*len(flag)
server.sendline(test_str)
# faccio un procedimento simile a quello fatto per il flag
enc_msg = server.recv(2048).decode().split("\n")[0]
enc_msg = bytes.fromhex(enc_msg)
server.close()

keystream = strxor(test_str, enc_msg[:len(test_str)])
print("FLAG", strxor(flag, keystream).decode())