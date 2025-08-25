# As part of a project to enhance the security of communication in a peer-to-peer file
# sharing system, you are tasked with implementing a secure key exchange
# mechanism using the Diffie-Hellman algorithm. Each peer must establish a shared
# secret key with another peer over an insecure channel. Implement the Diffie-
# Hellman key exchange protocol, enabling peers to generate their public and private
# keys and securely compute the shared secret key. Measure the time taken for key
# generation and key exchange processes.
from Crypto.Util.number import *
import random

def gen_public_params():
    p = getPrime(256)
    g = random.randint(1, p)
    return g, p

def gen_params(g, p):
    x = random.randint(1, p)
    G = pow(g, x, p)

    return x, G

class Alice:
    def __init__(self, g, p):
        self.g, self.p = g, p
        self.a, self.A = gen_params(g, p)
        self.shared_secret = None

    def compute_shared_secret(self, B):
        self.shared_secret = self.a * B

class Bob:
    def __init__(self, g, p):
        self.g, self.p = g, p
        self.b, self.B = gen_params(g, p)
        self.shared_secret = None

    def compute_shared_secret(self, A):
        self.shared_secret = self.b * A

if __name__ == "__main__":
    g, p = gen_public_params()
    # at alice
    a, A = gen_params(g, p)

    # at bob
    b, B = gen_params(g, p)