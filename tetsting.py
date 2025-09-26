from Crypto.Util.number import *
from sage.all import *

def add_round_key(state, round_key):
    key_matrix = [list(bytearray(round_key[i:i+4])) for i in range(0, len(round_key), 4)]
    new_state = [[0, 0, 0, 0] for _ in range(4)]
    for r in range(4):
        for c in range(4):
            new_state[r][c] = state[r][c] ^ key_matrix[c][r]
            print(f"{state[r][c]} ^ {key_matrix[c][r]} = {state[r][c] ^ key_matrix[c][r] }")
    return new_state

state = [
    [1,2,3,4],
    [5,6,7,8],
    [9,10,11,12],
    [13,14,15,16]
]

round_key = bytes(bytearray([i for i in range(10, 10+16)]))
key_matrix = [list(bytearray(round_key[i:i+4])) for i in range(0, len(round_key), 4)]

ok = add_round_key(state, round_key)
print()
print(Matrix(key_matrix))
print()
print(Matrix(state))
print()
print(Matrix(ok))
