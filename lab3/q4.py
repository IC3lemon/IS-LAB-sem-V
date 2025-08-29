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
    sz = s * 1024 * 1024
    if not os.path.exists(f) or os.path.getsize(f) != sz:
        print(f"Generating dummy file: {f} ({s} MB)...")
        with open(f, "wb") as file:
            file.write(get_random_bytes(sz))
        print("File generated successfully.")

def rsa_enc(pf, pk):
    sk = get_random_bytes(24)
    c_rsa = PKCS1_OAEP.new(pk, hashAlgo=SHA256)
    esk = c_rsa.encrypt(sk)
    c_des = DES3.new(sk, DES3.MODE_EAX)
    n = c_des.nonce
    with open(pf, "rb") as f:
        p = f.read()
    c, t = c_des.encrypt_and_digest(p)
    return n + c + t, esk

def rsa_dec(ed, ek, prk):
    c_rsa = PKCS1_OAEP.new(prk, hashAlgo=SHA256)
    sk = c_rsa.decrypt(ek)
    n = ed[:16]
    c = ed[16:-16]
    t = ed[-16:]
    c_des = DES3.new(sk, DES3.MODE_EAX, nonce=n)
    p = c_des.decrypt_and_verify(c, t)
    return p

def ecc_enc(pf, pk):
    ek = ECC.generate(curve="secp256r1")
    epk = ek.public_key().pointQ
    esk = ek.d
    ss = epk.x * pk.x
    s = get_random_bytes(16)
    dk = PBKDF2(str(ss).encode(), s, dkLen=24, count=100000, hmac_hash_module=SHA256)
    c_des = DES3.new(dk, DES3.MODE_EAX)
    n = c_des.nonce
    with open(pf, "rb") as f:
        p = f.read()
    c, t = c_des.encrypt_and_digest(p)
    return n + c + t, epk.x.to_bytes() + epk.y.to_bytes()

def ecc_dec(ed, epk_b, prk):
    x = int.from_bytes(epk_b[:32], 'big')
    y = int.from_bytes(epk_b[32:], 'big')
    epk = ECC.EccPoint(x, y, curve="secp256r1")
    ss = prk.d * epk.x
    s = ed[:16]
    dk = PBKDF2(str(ss).encode(), s, dkLen=24, count=100000, hmac_hash_module=SHA256)
    n = ed[:16]
    c = ed[16:-16]
    t = ed[-16:]
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
    e_1, ek_1 = rsa_enc(sf, rk.public_key())
    res["RSA"]["1me"] = time.perf_counter() - st
    st = time.perf_counter()
    d_1 = rsa_dec(e_1, ek_1, rk)
    res["RSA"]["1md"] = time.perf_counter() - st
    st = time.perf_counter()
    e_10, ek_10 = rsa_enc(lf, rk.public_key())
    res["RSA"]["10me"] = time.perf_counter() - st
    st = time.perf_counter()
    d_10 = rsa_dec(e_10, ek_10, rk)
    res["RSA"]["10md"] = time.perf_counter() - st
    
    print("\n--- Testing ECC (secp256r1) ---")
    st = time.perf_counter()
    ek = ECC.generate(curve="secp256r1")
    res["ECC"]["kgt"] = time.perf_counter() - st
    st = time.perf_counter()
    e_1_ecc, e_1_epk_b = ecc_enc(sf, ek.public_key().pointQ)
    res["ECC"]["1me"] = time.perf_counter() - st
    st = time.perf_counter()
    d_1_ecc = ecc_dec(e_1_ecc, e_1_epk_b, ek)
    res["ECC"]["1md"] = time.perf_counter() - st
    st = time.perf_counter()
    e_10_ecc, e_10_epk_b = ecc_enc(lf, ek.public_key().pointQ)
    res["ECC"]["10me"] = time.perf_counter() - st
    st = time.perf_counter()
    d_10_ecc = ecc_dec(e_10_ecc, e_10_epk_b, ek)
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
