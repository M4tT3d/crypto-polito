import pwn
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.Padding import pad

# il server è vulnerabile ad un attacco di tipo copy&paste
# il server usa AES in modalità ECB per cifrare il cookie che ci restituisce
# questo consente ad un attaccante di forgiare un cookie che abbia admin come
# ruolo ottenendo il flag

def main():
    username = b"A" * 7 + pad(b"true", 16) + pad(b"a", 9)
    print("USERNAME", username)
    server = pwn.connect("130.192.5.212", 6552)
    print(server.recv(1024))
    server.sendline(username)
    cookie = server.recv(1024).decode().strip()
    print("COOKIE", cookie)
    print("COOKIE BYTE", long_to_bytes(int(cookie)))
    cookie = long_to_bytes(int(cookie))
    cookie_username = cookie[:16]
    cookie_role= cookie[16:32]
    cookie_role_tag = cookie[32:48]
    cookie_rest = cookie[48:]
    print("COOKIE USERNAME", cookie_username)
    print("COOKIE ROLE", cookie_role)
    print("COOKIE ROLE TAG", cookie_role_tag)
    print(server.recv(1024))
    server.sendline(b"flag")
    print(server.recv(1024))
    print(cookie_username+cookie_role_tag+cookie_role)
    print("COOKIE in long int", bytes_to_long(cookie_username+cookie_role_tag+cookie_role ))
    server.sendline(str(bytes_to_long(cookie_username+cookie_role_tag+cookie_role )).encode())
    print(server.recv(1024).decode())
    server.close()

if __name__ == "__main__":
    main()
