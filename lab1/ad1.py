import string
charset = string.ascii_uppercase

ct = "NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"
for k in range(26):
    pt = ""
    for i in ct:
        if i in charset:
            pt += charset[(charset.index(i) - k) % 26]
        else: pt += i

    print(f"{k} : {pt}") # 11 : CRYPTOGRAPH/ANDSTEGANOGRAPHYARETWOSIDESODAC&QN