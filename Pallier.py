from Crypto.Util.number import getPrime, GCD, inverse
from random import randint

# === Key Generation ===
def keygen(bits=512):
    p = getPrime(bits)
    q = getPrime(bits)
    n = p * q
    lam = (p-1)*(q-1) // GCD(p-1, q-1)   # Carmichael’s function

    g = n + 1                            # common choice for g
    n2 = n * n

    # Precompute μ = (L(g^λ mod n²))⁻¹ mod n
    def L(u): return (u - 1) // n
    mu = inverse(L(pow(g, lam, n2)), n)

    pubkey = (n, g)
    privkey = (lam, mu)
    return pubkey, privkey

# === Encryption ===
def encrypt(m, pubkey):
    n, g = pubkey
    n2 = n*n
    while True:
        r = randint(1, n-1)
        if GCD(r, n) == 1:
            break
    c = (pow(g, m, n2) * pow(r, n, n2)) % n2
    return c

# === Decryption ===
def decrypt(c, pubkey, privkey):
    n, g = pubkey
    lam, mu = privkey
    n2 = n*n
    def L(u): return (u - 1) // n
    u = pow(c, lam, n2)
    m = (L(u) * mu) % n
    return m

# === Demo ===
if __name__ == "__main__":
    pub, priv = keygen(256)   # small for demo

    m1, m2 = 42, 99
    print("Plaintexts:", m1, m2)

    c1 = encrypt(m1, pub)
    c2 = encrypt(m2, pub)

    d1 = decrypt(c1, pub, priv)
    d2 = decrypt(c2, pub, priv)

    print("Decrypted:", d1, d2)

    # Homomorphic property: E(m1) * E(m2) mod n² = E(m1 + m2)
    n, g = pub
    n2 = n*n
    c_add = (c1 * c2) % n2
    d_add = decrypt(c_add, pub, priv)
    print("Decrypted sum:", d_add, "expected:", m1+m2)
