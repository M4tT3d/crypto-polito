from hlextend import sha256
from binascii import unhexlify, hexlify


coupon = unhexlify("757365726e616d653d746573742676616c75653d3130")
mac = "ab68c7c4ac21e6241631c4f902ff10cf6f06efce09b7e5c66db0a8a3975489ad"
mac = bytes.fromhex(mac)
h = sha256()
new_message = h.extend(b"&value=101", b"username=test&value=10", 16, mac.hex())
new_mac = h.hexdigest()
print("New Message: ", hexlify(new_message).decode())
print("New MAC:", new_mac)
