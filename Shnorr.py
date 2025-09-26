from Crypto.Util.number import getPrime, bytes_to_long
from hashlib import sha256
from random import randint

# === Key Generation ===
q = getPrime(160)              # subgroup order (small prime)
p = 2*q + 1                    # safe prime (for demo, not cryptographically strong)
g = 2                          # generator (works since p=2q+1)
x = randint(1, q-1)            # private key
y = pow(g, x, p)               # public key

print("Public key: (p, q, g, y)")
print("Private key: x\n")

# === Signing ===
m = b"message to sign"
k = randint(1, q-1)            # random nonce
r = pow(g, k, p)               # commitment

# Hash challenge
e = int.from_bytes(sha256(m + str(r).encode()).digest(), "big") % q

s = (k + x*e) % q              # response
signature = (e, s)

print("Signature (e, s):", signature)

# === Verification ===
# recompute r' = g^s * y^(-e) mod p
lhs = pow(g, s, p)
rhs = pow(y, -e % q, p)        # modular inverse trick
r_prime = (lhs * rhs) % p

e_prime = int.from_bytes(sha256(m + str(r_prime).encode()).digest(), "big") % q

print("Verification:", e == e_prime)
