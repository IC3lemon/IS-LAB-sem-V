# Encrypt   the   message   "Top   Secret   Data"   using   AES-192   with   the   key
# "FEDCBA9876543210FEDCBA9876543210". Show all the steps involved in the
# encryption process (key expansion, initial round, main rounds, final round).

from q2 import * # copy q2 code lmao, just fix NROUNDS 

msg = b"Top Secret Data"
key = bytes.fromhex("FEDCBA9876543210FEDCBA9876543210")

ct = encrypt(msg, key)
print(ct)
pt = decrypt(ct, key)
print(pt)
assert pt == b"Top Secret Data"