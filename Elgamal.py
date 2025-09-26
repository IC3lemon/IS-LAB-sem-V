from Crypto.Util.number import *
import random
m = b'Pakoda'

p = getPrime(256)
g = random.randint(2, p-1)
d = random.randint(1, p-2)
h = pow(g, d, p)

# public -> (p, g, h)

# encrypt 
r = random.randint(2, p-1)
c1 = pow(g, r, p)
c2 = (pow(h, r, p) * bytes_to_long(m)) % p 

print(f"{c1 = }\n{c2 = }")
m = (inverse(pow(c1, d, p), p) * c2) % p 

print(long_to_bytes(m))
# sign
m = b'Pakoda'
k = random.randint(2, p-2)
while GCD(k, p-1) != 1:
    k = random.randint(2, p-2)
k_inv = inverse(k, p-1)
r = pow(g, k, p) % (p-1)
s = (k_inv * (bytes_to_long(m) - d * r)) % (p-1)

# signature is (r, s)
print(f"{r = }\n{s = }")
# to check
v1 = pow(h, r, p) * pow(r, s, p) % p
v2 = pow(g, bytes_to_long(m), p)

print(v1 == v2)