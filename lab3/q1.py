# Using RSA, encrypt the message "Asymmetric Encryption" with the public key (n,
# e). Then decrypt the ciphertext with the private key (n, d) to verify the original
# message.
from Crypto.Util.number import *

def encrypt(m, pubkey):
    n, e = pubkey
    return long_to_bytes(pow(bytes_to_long(m), e, n))

def decrypt(c, privkey):
    n, d = privkey
    return long_to_bytes(pow(bytes_to_long(c), d, n))

msg = b'Asymmetric Encryption'
p, q = getPrime(1024), getPrime(1024)
n = p * q
e = 0x10001
d = inverse(e, (p-1)*(q-1))

pubkey = (n, e)
privkey = (n, d)
ct = encrypt(msg, pubkey)
print(f"{ct = }")
pt = decrypt(ct, privkey)
assert pt == b'Asymmetric Encryption'
print(f"{pt = }")