import sys
from BitVector import *
from rsa import RSA
from solve_pRoot import solve_pRoot

def encryption(plaintext, text1, text2, text3, ntext):
    rsa = RSA(e=3)
    file=open(plaintext, "r")
    #text1=open(text1, "w")
    #text2=open(text2, "w")
    #text3=open(text3, "w")
    ntext = open(ntext, "w")

    rsa.keyGen("p.txt", "q.txt")
    rsa.p = open("p.txt", "r")
    rsa.q = open("q.txt", "r")
    rsa.encrypt(plaintext, text1)
    #print(rsa.p, rsa.q, rsa.n)
    next = ""
    next = str(rsa.n) + ' '
    rsa.keyGen("p.txt", "q.txt")
    rsa.p = open("p.txt", "r")
    rsa.q = open("q.txt", "r")
    rsa.encrypt(plaintext, text2)
    #print(rsa.p, rsa.q, rsa.n)
    next += str(rsa.n) + ' '
    rsa.p = open("p.txt", "r")
    rsa.q = open("q.txt", "r")
    rsa.keyGen("p.txt", "q.txt")
    rsa.encrypt(plaintext, text3)
    next += str(rsa.n) 
    print(next)
    ntext.write(next)
    #print(rsa.p, rsa.q, rsa.n)
    return

def crack(text1, text2, text3, ntext, crackedtext):
    rsa = RSA(e=3)
    ntext=open(ntext, "r")
    C1 = open(text1, "r")
    C2 = open(text2, "r")
    C3 = open(text3, "r")
    
    #
    content = ntext.readline()
    numlist = content.split()
    n1 = int(numlist[0])
    n2 = int(numlist[1])
    n3 = int(numlist[2])
    #print(n1, n2, n3)
    N = n1 * n2 * n3
    #M^3 modulo N = n1 × n2 × n3
    bitC1 = BitVector(hexstring=C1.read())
    bitC2 = BitVector(hexstring=C2.read())
    bitC3 = BitVector(hexstring=C3.read())
    print(bitC1.length())
    C1 = bitC1.int_val()
    C2 = bitC2.int_val()
    C3 = bitC3.int_val()
    #print(C1)
    divided1 = N // n1
    divided2 = N // n2
    divided3 = N // n3
    bitn1 = BitVector(intVal=n1)
    bitn2 = BitVector(intVal=n2)
    bitn3 = BitVector(intVal=n3)
    bit_divided1 = BitVector(intVal = divided1)
    bit_divided2 = BitVector(intVal = divided2)
    bit_divided3 = BitVector(intVal = divided3)
    MI1 = int(bit_divided1.multiplicative_inverse(bitn1))
    MI2 = int(bit_divided2.multiplicative_inverse(bitn2))
    MI3 = int(bit_divided3.multiplicative_inverse(bitn3))
    
    crackedtext = open(crackedtext, "w")
    for x in range(0, len(bitC1) // 256):
        bv1 = int(bitC1[slice(x * 256, (x + 1) * 256)])
        bv2 = int(bitC2[slice(x * 256, (x + 1) * 256)])
        bv3 = int(bitC3[slice(x * 256, (x + 1) * 256)])
        cubedtext = (bv1 * divided1 * MI1 + bv2 * divided2 * MI2 + bv3 * divided3 * MI3) % N
        final = solve_pRoot(3, cubedtext)
        result = BitVector(intVal=final, size=128)
        crackedtext.write(result.get_bitvector_in_ascii())
    return


if __name__ == '__main__':
    if sys.argv[1] == "-e":
        encryption(plaintext = sys.argv[2], text1 = sys.argv[3], text2 = sys.argv[4], text3 = sys.argv[5], ntext = sys.argv[6])
    elif sys.argv[1] == "-c":
        crack(text1 = sys.argv[2], text2 = sys.argv[3], text3 = sys.argv[4], ntext = sys.argv[5], crackedtext = sys.argv[6])
