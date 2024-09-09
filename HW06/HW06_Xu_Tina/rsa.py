'''
Homework Number: 6
Name: Tina Xu 
ECN Login: xu1493
Due Date: 02/27/2023 
'''
import sys
from BitVector import *
from PrimeGenerator import PrimeGenerator

class RSA:
    def __init__(self, e) -> None:
        self.e = e
        self.n = None
        self.d = None
        self.p = None
        self.q = None

    # You are free to have other RSA class methods you deem necessary for your solution
    def readfile(self, filename: str) -> int:
        with open(filename, 'r') as file:
            return int(file.read())
    def gcd(self, a, b):
        while b:
            a, b = b, a % b
        return a

    def keyGen(self, ptext, qtext):
        ptext = open(ptext, "w")
        qtext = open(qtext, "w")
        gen = PrimeGenerator(bits=128)
        self.p = gen.findPrime()
        self.q = gen.findPrime()
        #print(self.p, self.q)
        while self.gcd((self.p-1), 3) != 1:
            self.p = gen.findPrime()
        
        while self.gcd((self.q-1), 3) != 1 or self.p == self.q:
            self.q = gen.findPrime()
        ptext.write(str(self.p))
        qtext.write(str(self.q))
        return self.p, self.q

    def encrypt(self, plaintext: str, ciphertext: str) -> None:
        # Your implementation goes here
        self.p = self.readfile("p.txt")
        self.q = self.readfile("q.txt")
        file=open(ciphertext, "w")
        bve = BitVector(filename=plaintext)
        n=0
        #print(self.p, self.q)
        while (bve.more_to_read):
            n+=1
            bv = bve.read_bits_from_file(128)
            if bv._getsize()> 0 & bv._getsize() < 128:
                zero = 128 - bv._getsize()
                bv.pad_from_right(zero)
            bv.pad_from_left(128)
            self.n = (self.p) * (self.q)
            bite = BitVector(intVal = self.e)
            bitn = BitVector(intVal = self.n)
            bitd = (bite).multiplicative_inverse(bitn)
            self.d = bitd.int_val()
            #print(n)
            # C = M^e mod n
            encrypt = pow(bv.int_val(), self.e, self.n)
            encrypt = BitVector(intVal=encrypt, size=256)
            file.write(encrypt.get_bitvector_in_hex())
            #file.write(str(encrypt))
        pass

    def decrypt(self, ciphertext: str, recovered_plaintext: str) -> None:
        # Your implementation goes here
        self.p = self.readfile("p.txt")
        self.q = self.readfile("q.txt")
        #print(self.q, self.p)
        file=open(ciphertext, "r")
        fileout = open(recovered_plaintext, "w")
        p = BitVector(intVal = self.p)
        q = BitVector(intVal = self.q)
        pi = int((p).multiplicative_inverse(q))
        qi = int((q).multiplicative_inverse(p))
        Xp = (self.q) * qi
        Xq = (self.p) * pi
        #bv = BitVector(intVal = file.read())
        #ciphertext = int(hexstring = file.read())
        bve = BitVector(hexstring = file.read())
        self.n = (self.p) * (self.q)
        totient = (self.p-1) * (self.q-1)
        bite = BitVector(intVal = self.e)
        bitto = BitVector(intVal = totient)
        bitd = (bite).multiplicative_inverse(bitto)
        self.d = bitd.int_val()
        #print(self.d, self.n)
        for i in range(0, len(bve) // 256):
            bv = bve[slice(i * 256, (i + 1) * 256)]
            #decrypt = pow(bv.int_val(), self.d, self.n)
            Vp = pow(bv.int_val(), self.d, self.p)
            Vq = pow(bv.int_val(), self.d, self.q)
            decrypt = (Vp * Xp + Vq * Xq) % (self.n)
            #print(decrypt)
            decrypt = BitVector(intVal = decrypt, size=128)
            decrypt = decrypt.get_bitvector_in_ascii()
            fileout.write(decrypt)
        pass

if __name__ == "__main__":
    cipher = RSA(e=65537)
    if sys.argv[1] == "-g":
        cipher.keyGen(sys.argv[2], sys.argv[3])
    if sys.argv[1] == "-e":
        cipher.encrypt(plaintext=sys.argv[2], ciphertext=sys.argv[5])
    elif sys.argv[1] == "-d":
        cipher.decrypt(ciphertext=sys.argv[2], recovered_plaintext=sys.argv[5])









