# vulnerabile a low public exponent attack -> failed
# però era possibile fattorizzare n e calcolare d
from gmpy2.gmpy2 import iroot
from Crypto.Util.number import long_to_bytes, inverse
from factordb.factordb import FactorDB

n = 770071954467068028952709005868206184906970777429465364126693
e = 3
ct = 388435672474892257936058543724812684332943095105091384265939

[decrypted_int, exact] = iroot(ct, e)
print(decrypted_int)
if exact:
    print(long_to_bytes(pow(decrypted_int, 1/e)))
    exit(0)
db = FactorDB(n)
db.connect()
factors = db.get_factor_list()
if len(factors) != 2:
    print("Failed to factor n")
    exit(1)
p, q = factors
phi = (p - 1) * (q - 1)
d = inverse(e, phi)
print(long_to_bytes(pow(ct, d, n)))