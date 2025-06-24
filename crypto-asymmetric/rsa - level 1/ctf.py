from factordb.factordb import FactorDB
from Crypto.Util.number import inverse, long_to_bytes

n = 176278749487742942508568320862050211633
chiphertext = 46228309104141229075992607107041922411
f = FactorDB(n)
f.connect()
[p, q] = f.get_factor_list()
n = p*q
phi = (p-1)*(q-1)
e = 65537
d = inverse(e, phi)
flag = pow(chiphertext, d, n)
print(long_to_bytes(flag))