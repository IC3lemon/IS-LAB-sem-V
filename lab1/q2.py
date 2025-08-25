import string
charset = string.ascii_uppercase

class A:
    def __init__(self, msg, key):
        self.pt = msg
        self.key = key
        self.ct = ""

    def encrypt(self):
        self.ct = ""
        for i, j in zip(self.pt, (self.key*50)[:len(self.pt)]):
            if i.upper() in charset:
                ok = charset[(charset.index(i.upper()) + charset.index(j.upper())) % 26]
                if i.isupper(): self.ct += ok
                else: self.ct += ok.lower()
            else:
                self.ct += i

        return self.ct

    def decrypt(self):
        self.pt = ""
        for i, j in zip(self.ct, (self.key*50)[:len(self.pt)]):
            if i.upper() in charset:
                ok = charset[(charset.index(i.upper()) - charset.index(j.upper())) % 26]
                if i.isupper(): self.pt += ok
                else: self.pt += ok.lower()
            else:
                self.pt += i

        return self.pt

if __name__ == "__main__":
    msg = "the house is being sold tonight"
    a = A(msg, 'dollars')
    print(a.encrypt())
    print(a.decrypt())