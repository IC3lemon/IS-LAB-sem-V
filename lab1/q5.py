# John is reading a mystery book involving cryptography. In one part of the book, the
# author gives a ciphertext "CIW" and two paragraphs later the author tells the reader that
# this is a shift cipher and the plaintext is "yes". In the next chapter, the hero found a tablet
# in a cave with "XVIEWYWI" engraved on it. John immediately found the actual meaning
# of the ciphertext.  Identify the type of attack and plaintext.
import string
# Known-plaintext attack
# C -> Y
# I -> E
# W -> S
charset = string.ascii_uppercase
# print((charset.index('C') - charset.index('Y')) % 26) # 4
# print((charset.index('I') - charset.index('E')) % 26) # 4 
# print((charset.index('W') - charset.index('S')) % 26) # 4
rot = - ((charset.index('C') - charset.index('Y')) % 26)
ct = 'XVIEWYWI'
pt = "".join(charset[(charset.index(c) - 4) % 26] for c in ct)
print(pt) # TREASUSE