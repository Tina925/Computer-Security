from BitVector import *
from PrimeGenerator import PrimeGenerator
import sys

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def key_gen(p_txt, q_txt):
    f_1 = open(p_txt, "w")
    f_2 = open(q_txt, "w")
    generator = PrimeGenerator(bits=128)
    
    p = generator.findPrime()
    while gcd(p - 1, 65537) != 1:
        p = generator.findPrime()

    q = generator.findPrime()
    while gcd(q - 1, 65537) != 1 or p == q:
        q = generator.findPrime()

    f_1.write(str(p))
    f_2.write(str(q))
    return

def encryption(input, p_txt, q_txt, output):
    f_p = open(p_txt, "r")
    f_q = open(q_txt, "r")

    p = int(f_p.read())
    q = int(f_q.read())
    n = p * q
    e = 65537
    print(p, q)
    bv = BitVector(filename=input)
    f = open(output, "w")

    while bv.more_to_read:
        bitvec = bv.read_bits_from_file(128)

        if bitvec._getsize() > 0:
            if bitvec._getsize() < 128:
                numZero = 128 - bitvec._getsize()
                bitvec.pad_from_right(numZero)

        bitvec.pad_from_left(128)
        bitVal = int(bitvec)
        encrypted_val = pow(bitVal, e, n)
        encrypted_bit = BitVector(intVal=encrypted_val, size=256)
        f.write(encrypted_bit.get_bitvector_in_hex())
    return

def decryption(input, p_txt, q_txt, output):
    f_p = open(p_txt, "r")
    f_q = open(q_txt, "r")

    p = int(f_p.read())
    q = int(f_q.read())

    p_bit = BitVector(intVal=p)
    q_bit = BitVector(intVal=q)
    p_inv = int(p_bit.multiplicative_inverse(q_bit))
    q_inv = int(q_bit.multiplicative_inverse(p_bit))

    Xp = q * q_inv
    Xq = p * p_inv
    n = p * q

    tot = (p - 1) * (q - 1)
    tot_modulus = BitVector(intVal=tot)

    e = BitVector(intVal=65537)
    d = e.multiplicative_inverse(tot_modulus)
    eVal = int(e)
    dVal = int(d)

    f_in = open(input, "r")
    bv = BitVector(hexstring=f_in.read())
    f_out = open(output, "w")

    for i in range(0, len(bv) // 256):
        bitvec = bv[i * 256:(i + 1) * 256]
        bitVal = int(bitvec)
        Vp = pow(bitVal, dVal, p)
        Vq = pow(bitVal, dVal, q)
        decrypted_val = (Vp * Xp + Vq * Xq) % n
        decrypted_bit = BitVector(intVal=decrypted_val, size=128)
        f_out.write(decrypted_bit.get_bitvector_in_ascii())
    return

if __name__ == '__main__':
    if sys.argv[1] == "-g":
        key_gen(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "-e":
        encryption(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    elif sys.argv[1] == "-d":
        decryption(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])




from BitVector import BitVector
from sympy import solve_pRoot

def cracking_enc(enc1, enc2, enc3, n_input, output):
    # Read in public keys
    with open(n_input, "r") as f_n:
        input_data = f_n.readlines()
    n1, n2, n3 = map(int, input_data)

    # Read in encrypted files
    with open(enc1, "r") as f_1:
        bv_1 = BitVector(hexstring=f_1.read())
    
    with open(enc2, "r") as f_2:
        bv_2 = BitVector(hexstring=f_2.read())
    
    with open(enc3, "r") as f_3:
        bv_3 = BitVector(hexstring=f_3.read())

    M1 = BitVector(intVal=n2 * n3)
    M1_inverse = M1.multiplicative_inverse(BitVector(intVal=n1))
    M2 = BitVector(intVal=n1 * n3)
    M2_inverse = M2.multiplicative_inverse(BitVector(intVal=n2))
    M3 = BitVector(intVal=n1 * n2)
    M3_inverse = M3.multiplicative_inverse(BitVector(intVal=n3))
    C1 = int(M1) * int(M1_inverse)
    C2 = int(M2) * int(M2_inverse)
    C3 = int(M3) * int(M3_inverse)

    # Open output file for writing
    with open(output, "w") as f_out:
        for i in range(0, len(bv_1) // 256):
            bitvec_1 = bv_1[i * 256:(i + 1) * 256]
            bitvec_2 = bv_2[i * 256:(i + 1) * 256]
            bitvec_3 = bv_3[i * 256:(i + 1) * 256]

            A = (int(bitvec_1) * C1 + int(bitvec_2) * C2 + int(bitvec_3) * C3) % (n1 * n2 * n3)
            cracked = solve_pRoot(3, A)
            cracked_bv = BitVector(intVal=cracked, size=128)
            f_out.write(cracked_bv.get_bitvector_in_ascii())
