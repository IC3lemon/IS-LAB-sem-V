# encrypt "Confidential Data"
# key : "A1B2C3D4"
def long_to_bytes(long : int):
    return int.to_bytes(long, 8, 'big')

def bytes_to_long(byts : bytes):
    return int.from_bytes(byts)

def pad(pt):
    while len(pt) % 8 != 0:
        pt += b'\x00'
    return pt

def initial_permute(block):
    block_bits = bin(bytes_to_long(block))[2:].zfill(64)
    assert len(block_bits) == 64, "weird block bro"
    p_box = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 26, 8,
        57, 49, 41, 33, 25, 17, 9,  1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]
    return long_to_bytes(int(''.join(block_bits[p_box[i]-1] for i in range(64)), 2))

def PC2(block):
    block_bits = bin(bytes_to_long(block))[2:].zfill(56)
    p_box = [
        14, 17, 11, 24, 1, 5, 3, 28,
        15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44 , 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32
    ]
    permuted_block = ""
    return long_to_bytes(int(''.join(block_bits[p_box[i]-1] for i in range(48)), 2))

def get_round_keys(key):
    key_bits = bin(bytes_to_long(key))[2:].zfill(64)
    print(key_bits)
    assert len(key_bits) == 64, "weird key bro"
    # PC 1
    key_ = '' # 56 bit key
    for i in range(len(key_bits)):
        if (i+1) % 8 == 0:
            continue
        key_ += key_bits[i]

    c, d = key_[:28], key_[28:]
    round_keys = []
    for i in range(16):
        if i in [0,1,8,15]:
            c_ = c[1:] + c[0]
            d_ = d[1:] + c[0]
        else:
            c_ = c[2:] + c[:2]
            d_ = d[2:] + d[:2]

        round_keys.append(PC2(long_to_bytes(int(c_ + d_, 2))))
        c, d = c_, d_

    for k in round_keys:
        assert len(bin(bytes_to_long(k))[2:].zfill(48)) == 48
    return round_keys

def F(rpt):
    assert len(bin(bytes_to_long(rpt))[2:].zfill(32)) == 32

def feistal_round(block : bytes, key : bytes):
    block = initial_permute(block)
    lpt = block[:4]
    rpt = block[4:]
    assert len(bin(bytes_to_long(lpt))[2:].zfill(32)) == 32
    assert len(bin(bytes_to_long(rpt))[2:].zfill(32)) == 32

    rpt = F(rpt)


MSG = pad(b"Confidential Data")
blocks = [MSG[i:i+8] for i in range(0, len(MSG), 8)]
KEY = b"A1B2C3D4"

