import os
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, DES3
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA256

def gen_file(f, s):
    """Generates a dummy file of a specified size in MB."""
    sz = s * 1024 * 1024
    if not os.path.exists(f) or os.path.getsize(f) != sz:
        print(f"Generating dummy file: {f} ({s} MB)...")
        with open(f, "wb") as file:
            file.write(get_random_bytes(sz))
        print("File generated successfully.")

def rsa_enc(pf, pk):
    """Encrypts a file using RSA for key exchange and DES3 for file encryption."""
    # Generate a random 24-byte session key for DES3
    sk = get_random_bytes(24)
    # Encrypt the session key with the recipient's RSA public key
    c_rsa = PKCS1_OAEP.new(pk, hashAlgo=SHA256)
    esk = c_rsa.encrypt(sk)
    # Encrypt the file using the session key and DES3
    c_des = DES3.new(sk, DES3.MODE_EAX)
    n = c_des.nonce
    with open(pf, "rb") as f:
        p = f.read()
    c, t = c_des.encrypt_and_digest(p)
    return n, c, t, esk

def rsa_dec(n, c, t, ek, prk):
    """Decrypts a file using RSA for key exchange and DES3 for file encryption."""
    # Decrypt the session key with the recipient's RSA private key
    c_rsa = PKCS1_OAEP.new(prk, hashAlgo=SHA256)
    sk = c_rsa.decrypt(ek)
    # Decrypt the file using the session key and DES3
    c_des = DES3.new(sk, DES3.MODE_EAX, nonce=n)
    p = c_des.decrypt_and_verify(c, t)
    return p

def ecc_enc(pf, pk):
    """Encrypts a file using ECC for key exchange (ECDH) and DES3 for file encryption."""
    # Generate an ephemeral ECC key pair
    ek = ECC.generate(curve="secp256r1")
    epk = ek.public_key().pointQ
    # Derive a shared secret using ECDH
    ss = (ek.d * pk.pointQ).x
    # Derive the DES3 session key from the shared secret with a salt
    s = get_random_bytes(16)
    # Hash the shared secret to a consistent size for PBKDF2
    h = SHA256.new(int(ss).to_bytes((int(ss).bit_length() + 7) // 8, 'big')).digest()
    dk = PBKDF2(h, s, dkLen=24, count=100000, hmac_hash_module=SHA256)
    # Encrypt the file using the derived session key and DES3
    c_des = DES3.new(dk, DES3.MODE_EAX)
    n = c_des.nonce
    with open(pf, "rb") as f:
        p = f.read()
    c, t = c_des.encrypt_and_digest(p)
    # Return the salt and ephemeral public key for decryption
    return n, c, t, s, epk.x.to_bytes() + epk.y.to_bytes()

def ecc_dec(n, c, t, s, epk_b, prk):
    """Decrypts a file using ECC for key exchange (ECDH) and DES3 for file encryption."""
    # Reconstruct the ephemeral public key
    x = int.from_bytes(epk_b[:32], 'big')
    y = int.from_bytes(epk_b[32:], 'big')
    epk = ECC.EccPoint(x, y, curve="secp256r1")
    # Derive the shared secret using ECDH
    ss = (prk.d * epk).x
    # Hash the shared secret to a consistent size for PBKDF2
    h = SHA256.new(int(ss).to_bytes((int(ss).bit_length() + 7) // 8, 'big')).digest()
    dk = PBKDF2(h, s, dkLen=24, count=100000, hmac_hash_module=SHA256)
    # Decrypt the file using the derived session key and DES3
    c_des = DES3.new(dk, DES3.MODE_EAX, nonce=n)
    p = c_des.decrypt_and_verify(c, t)
    return p

def main():
    sf = "1MB_file.txt"
    lf = "10MB_file.txt"
    gen_file(sf, 1)
    gen_file(lf, 10)
    res = {
        "RSA": {"kgt": 0, "1me": 0, "1md": 0, "10me": 0, "10md": 0},
        "ECC": {"kgt": 0, "1me": 0, "1md": 0, "10me": 0, "10md": 0}
    }
    
    print("\n--- Testing RSA (2048-bit) ---")
    st = time.perf_counter()
    rk = RSA.generate(2048)
    res["RSA"]["kgt"] = time.perf_counter() - st
    st = time.perf_counter()
    n_1, c_1, t_1, ek_1 = rsa_enc(sf, rk.public_key())
    res["RSA"]["1me"] = time.perf_counter() - st
    st = time.perf_counter()
    d_1 = rsa_dec(n_1, c_1, t_1, ek_1, rk)
    res["RSA"]["1md"] = time.perf_counter() - st
    st = time.perf_counter()
    n_10, c_10, t_10, ek_10 = rsa_enc(lf, rk.public_key())
    res["RSA"]["10me"] = time.perf_counter() - st
    st = time.perf_counter()
    d_10 = rsa_dec(n_10, c_10, t_10, ek_10, rk)
    res["RSA"]["10md"] = time.perf_counter() - st
    
    print("\n--- Testing ECC (secp256r1) ---")
    st = time.perf_counter()
    ek = ECC.generate(curve="secp256r1")
    res["ECC"]["kgt"] = time.perf_counter() - st
    st = time.perf_counter()
    n_1_ecc, c_1_ecc, t_1_ecc, s_1_ecc, epk_b_1_ecc = ecc_enc(sf, ek.public_key())
    res["ECC"]["1me"] = time.perf_counter() - st
    st = time.perf_counter()
    d_1_ecc = ecc_dec(n_1_ecc, c_1_ecc, t_1_ecc, s_1_ecc, epk_b_1_ecc, ek)
    res["ECC"]["1md"] = time.perf_counter() - st
    st = time.perf_counter()
    n_10_ecc, c_10_ecc, t_10_ecc, s_10_ecc, epk_b_10_ecc = ecc_enc(lf, ek.public_key())
    res["ECC"]["10me"] = time.perf_counter() - st
    st = time.perf_counter()
    d_10_ecc = ecc_dec(n_10_ecc, c_10_ecc, t_10_ecc, s_10_ecc, epk_b_10_ecc, ek)
    res["ECC"]["10md"] = time.perf_counter() - st

    print("\n--- Performance Results ---")
    print(f"{'Metric':<25} | {'RSA (2048-bit)':<20} | {'ECC (secp256r1)':<20}")
    print("-" * 70)
    print(f"{'Key Generation':<25} | {res['RSA']['kgt']:.6f} s | {res['ECC']['kgt']:.6f} s")
    print(f"{'1MB Encryption':<25} | {res['RSA']['1me']:.6f} s | {res['ECC']['1me']:.6f} s")
    print(f"{'1MB Decryption':<25} | {res['RSA']['1md']:.6f} s | {res['ECC']['1md']:.6f} s")
    print(f"{'10MB Encryption':<25} | {res['RSA']['10me']:.6f} s | {res['ECC']['10me']:.6f} s")
    print(f"{'10MB Decryption':<25} | {res['RSA']['10md']:.6f} s | {res['ECC']['10md']:.6f} s")
    
    os.remove(sf)
    os.remove(lf)

if __name__ == "__main__":
    main()