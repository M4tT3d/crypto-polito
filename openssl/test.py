from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
from base64 import b64decode

# Base64 encoded ciphertext
ciphertext_base64 = "ZZJ+BKJNdpXA2jaX8Zg5ItRola18hi95MG8fA/9RPvg="
ciphertext = b64decode(ciphertext_base64)

# Key and IV (both 16 bytes in this example)
key = b"0123456789ABCDEF"  # 16 bytes key
iv = b"0123456789ABCDEF"   # 16 bytes IV

cipher = AES.new(key, AES.MODE_CBC, iv)
# print(cipher.encrypt(b"test test test t"))
print(cipher.decrypt(ciphertext))
