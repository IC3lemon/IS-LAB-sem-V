from Crypto.Cipher import AES, DES 
from Crypto.Util.Padding import *
import os
import time

# Compare the encryption and decryption times for DES and AES-256 for the
# message   "Performance   Testing   of   Encryption   Algorithms".   Use   a   standard
# implementation and report your findings.

key = os.urandom(32)
msg = pad(b"Performance   Testing   of   Encryption   Algorithms", 16)

aes = AES.new(key, AES.MODE_ECB)
des = DES.new(key[:8], DES.MODE_ECB)

start_time = time.time()
ct_aes = aes.encrypt(msg)
aes_time_enc = time.time() - start_time
print(f'AES encryption time : {aes_time_enc}ms') 

start_time = time.time()
ct_des = des.encrypt(msg)
des_time_enc = time.time() - start_time
print(f'DES encryption time : {des_time_enc}ms') 
alg = "AES" if aes_time_enc <= des_time_enc else "DES"
print(f"{alg} was faster at encrypting\n")


start_time = time.time()
pt = aes.decrypt(ct_aes)
aes_time_enc = time.time() - start_time
print(f'AES decryption time : {aes_time_enc}ms') 

start_time = time.time()
pt = des.decrypt(ct_des)
des_time_enc = time.time() - start_time
print(f'DES decryption time : {des_time_enc}ms') 
alg = "AES" if aes_time_enc <= des_time_enc else "DES"
print(f"{alg} was faster at decrypting\n")

# AES encryption time : 0.0008866786956787109ms
# DES encryption time : 1.6689300537109375e-05ms
# DES was faster at encrypting

# AES decryption time : 3.361701965332031e-05ms
# DES decryption time : 1.1444091796875e-05ms
# DES was faster at decrypting