import sys
from BitVector import *

class AES:
    def __init__(self, keyfile: str) -> None:
        # Class constructor - when creating an AES object, the class's constructor is executed, and instance variables are initialized
        self.keyfile = keyfile
        #self.key = self.get_encryption_key(self.keyfile)
        #print(self.key)
        self.AES_modulus = BitVector(bitstring='100011011')
        self.subBytesTable = []                                                  # for encryption
        self.invSubBytesTable = []                                               # for decryption
        self.genTables()                                         
        pass

    def genTables(self):
        c = BitVector(bitstring='01100011')
        d = BitVector(bitstring='00000101')
        for i in range(0, 256):
            # For the encryption SBox
            a = BitVector(intVal = i, size=8).gf_MI(self.AES_modulus, 8) if i != 0 else BitVector(intVal=0)
            # For bit scrambling for the encryption SBox entries:
            a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
            a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
            self.subBytesTable.append(int(a))
            # For the decryption Sbox:
            b = BitVector(intVal = i, size=8)
            # For bit scrambling for the decryption SBox entries:
            b1,b2,b3 = [b.deep_copy() for x in range(3)]
            b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
            check = b.gf_MI(self.AES_modulus, 8)
            b = check if isinstance(check, BitVector) else 0
            self.invSubBytesTable.append(int(b))


    def gee(self, keyword, round_constant, byte_sub_table):
        '''
        This is the g() function you see in Figure 4 of Lecture 8.
        '''
        rotated_word = keyword.deep_copy()
        rotated_word << 8
        newword = BitVector(size = 0)
        for i in range(4):
            newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
        newword[:8] ^= round_constant
        round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), self.AES_modulus, 8)
        return newword, round_constant
    
    def gen_key_schedule_256(self, key_bv):
        byte_sub_table = self.gen_subbytes_table()
        #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
        #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
        #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
        #  schedule. We will store all 60 keywords in the following list:
        key_words = [None for i in range(60)]
        round_constant = BitVector(intVal = 0x01, size=8)
        for i in range(8):
            key_words[i] = key_bv[i*32 : i*32 + 32]
        for i in range(8,60):
            if i%8 == 0:
                kwd, round_constant = self.gee(key_words[i-1], round_constant, byte_sub_table)
                key_words[i] = key_words[i-8] ^ kwd
            elif (i - (i//8)*8) < 4:
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            elif (i - (i//8)*8) == 4:
                key_words[i] = BitVector(size = 0)
                for j in range(4):
                    key_words[i] += BitVector(intVal = 
                                    byte_sub_table[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
                key_words[i] ^= key_words[i-8] 
            elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            else:
                sys.exit("error in key scheduling algo for i = %d" % i)
        return key_words

    def gen_subbytes_table(self):
        subBytesTable = []
        c = BitVector(bitstring='01100011')
        for i in range(0, 256):
            a = BitVector(intVal = i, size=8).gf_MI(self.AES_modulus, 8) if i != 0 else BitVector(intVal=0)
            a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
            a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
            subBytesTable.append(int(a))
        return subBytesTable
    
    def get_key_from_user(self):
        keysize = 256
        with open(self.keyfile, 'r') as f:
            key = f.read().strip()
        key += '0' * (keysize//8 - len(key)) if len(key) < keysize//8 else key[:keysize//8]  
        key_bv = BitVector( textstring = key )
        return keysize,key_bv
    
    def get_encryption_key(self, keyF):
        file = open(self.keyfile,"r")
        key = BitVector(textstring = file.readlines()[0])
        return key

    def encrypt(self, plaintext: str, ciphertext: str) -> None:
    # Open the plaintext file
        #with open(plaintext, 'rb') as file:
        #    plaintext = file.read()
        # Generate key schedule
        k = 0
        keysize, key_bv = self.get_key_from_user()
        key_words = []
        key_words = self.gen_key_schedule_256(key_bv)
        key_schedule = []
        for word_index,word in enumerate(key_words):
            keyword_in_ints = []
            for i in range(4):
                keyword_in_ints.append(word[i*8:i*8+8].intValue())
            key_schedule.append(keyword_in_ints)
        round_keys = [None for i in range(15)]
        for i in range(15):
            round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + key_words[i*4+3]).get_bitvector_in_hex()
 
        bv = BitVector(filename=plaintext)
        file=open(ciphertext, "w")
        state = [[0 for x in range(4)] for x in range(4)]
        n=0
        while (bv.more_to_read):
            n+=1
            print("n is", n)
            bv = bv.read_bits_from_file(128)
            if bv._getsize()> 0 & bv._getsize() < 128:
                zero = 128 - bv._getsize()
                bv.pad_from_right(zero)

                print("step0: ", bv.get_bitvector_in_hex())
                
                # xor
                round_key_bv = BitVector(hexstring=round_keys[0])
                bv = bv.__xor__(round_key_bv)
                print("step xor: ", bv.get_bitvector_in_hex(), len(bv))
                state = [[bv[i*32+j*8:i*32+j*8+8] for j in range(4)] for i in range(4)]
                for x in range(1, 15):
                    # Step 1: SubBytes
                    for i in range(4):
                        for j in range(4):
                            state[i][j] = BitVector(intVal=self.subBytesTable[int(state[i][j])], size=8)
                    
                    print("After SubBytes step:")
                    for i in range(4):
                        for j in range(4):
                            print(state[i][j].get_bitvector_in_hex(), end=' ')
                        print()
                    

                    # Step 2: ShiftRows
                    temp_shift = [0] * 4
                    for i in range(1, 4):       
                        for j in range(0, 4):
                            temp_shift[(j - i) % 4] = state[j][i]
                        for j in range(0, 4):
                            state[j][i] = temp_shift[j]
                    print("After shift row step:")
                    for i in range(4):
                        for j in range(4):
                            print(state[i][j].get_bitvector_in_hex(), end=' ')
                        print()

                    # Step 3: MixColumns (except for the last round)
                    if (x != 14):
                        for i in range(4):
                            temp = (BitVector(bitstring='00000010').gf_multiply_modular(state[i][0], self.AES_modulus, 8)) ^ (BitVector(bitstring='00000011').gf_multiply_modular(state[i][1], self.AES_modulus, 8)) ^ state[i][2] ^ state[i][3]
                            temp1 = (BitVector(bitstring='00000010').gf_multiply_modular(state[i][1], self.AES_modulus, 8)) ^ (BitVector(bitstring='00000011').gf_multiply_modular(state[i][2], self.AES_modulus, 8)) ^ state[i][3] ^ state[i][0]
                            temp2 = (BitVector(bitstring='00000010').gf_multiply_modular(state[i][2], self.AES_modulus, 8)) ^ (BitVector(bitstring='00000011').gf_multiply_modular(state[i][3], self.AES_modulus, 8)) ^ state[i][0] ^ state[i][1]
                            temp3 = (BitVector(bitstring='00000010').gf_multiply_modular(state[i][3], self.AES_modulus, 8)) ^ (BitVector(bitstring='00000011').gf_multiply_modular(state[i][0], self.AES_modulus, 8)) ^ state[i][1] ^ state[i][2]

                            state[i][0] = temp
                            state[i][1] = temp1
                            state[i][2] = temp2
                            state[i][3] = temp3
                        print("After mix column step:")
                        for i in range(4):
                            for j in range(4):
                                print(state[i][j].get_bitvector_in_hex(), end=' ')
                            print()
                    
                    # Step 4: AddRoundKey
                    round_keys[x] = (key_words[x * 4] + key_words[x * 4 + 1] + key_words[x * 4 + 2] + key_words[x * 4 + 3]).get_bitvector_in_hex()
                    print(round_keys[x])
                    finalhex = ""
                    for i in range(4):
                        for j in range(4):
                            finalhex += state[i][j].get_bitvector_in_hex()
                    print(finalhex)
                    finalvec = BitVector(hexstring = finalhex)
                    roundkey = BitVector(hexstring = round_keys[x])
                    finalvec = finalvec.__xor__(roundkey)
                    for i in range(4):
                        for j in range(4):
                            state[i][j] = finalvec[i*32+j*8:i*32+j*8+8] 
                    k+=1
                    print("\nk is", k)
                    print("after final", finalvec.get_bitvector_in_hex())
            final = ""
            for i in range(4):
                for j in range(4):
                    final += state[i][j].get_bitvector_in_hex()
            final = BitVector(hexstring = final)
            file.write(final.get_bitvector_in_hex())
            #file.close()
        pass
                 
            
    def decrypt(self, ciphertext: str, decrypted: str) -> None:
        # Decrypt - method performs AES decryption on the ciphertext and writes the recovered plaintext to disk
        # Inputs: ciphertext (str) - filename containing ciphertext
        #         decrypted (str) - filename containing recovered plaintext
        # Return: void

        file = open(ciphertext, "r")
        bv = BitVector(hexstring = file.read())
        # Generate key schedule
        keysize, key_bv = self.get_key_from_user()
        key_words = []
        key_words = self.gen_key_schedule_256(key_bv)
        key_schedule = []
        for word_index,word in enumerate(key_words):
            keyword_in_ints = []
            for i in range(4):
                keyword_in_ints.append(word[i*8:i*8+8].intValue())
            key_schedule.append(keyword_in_ints)
        round_keys = [None for i in range(15)]
        for i in range(15):
            round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + key_words[i*4+3]).get_bitvector_in_hex()
        #bv = BitVector(hexstring = encrypted)
        decryptedtext = ""
        state = [[0 for x in range(4)] for x in range(4)]
        with open(decrypted, "w", encoding="utf-8") as decrypted:
            if (len(bv) % 128 != 0):
                zero = 128 - len(bv) % 128
                bv.pad_from_right(zero)
            print("step0: ", bv.get_bitvector_in_hex(), len(bv))
            # xor
            round_key_bv = BitVector(hexstring=round_keys[14])
            bv = bv.__xor__(round_key_bv)
            # Step 1: Inverse ShiftRows
            k = 0
            for x in range(14, 0, -1):
                k = k + 1
                state = [[bv[i*32+j*8:i*32+j*8+8] for j in range(4)] for i in range(4)]
                temp_shift = [0] * 4
                for i in range(1, 4):       
                    for j in range(0, 4):
                        temp_shift[(j + i) % 4] = state[j][i]
                    for j in range(0, 4):
                        state[j][i] = temp_shift[j]

                print("\n\nk is:", k)

                # Step 2: Inverse ByteSubstitute
                for i in range(4):
                    for j in range(4):
                        state[i][j] = BitVector(intVal=self.invSubBytesTable[int(state[i][j])], size=8)

                # Step 3: add roundkey
                round_keys[x] = (key_words[x * 4] + key_words[x * 4 + 1] + key_words[x * 4 + 2] + key_words[x * 4 + 3]).get_bitvector_in_hex()
                finalhex = ""
                for i in range(4):
                    for j in range(4):
                        finalhex += state[j][i].get_bitvector_in_hex()

                wholevec = BitVector(hexstring=finalhex)
                roundkey = BitVector(hexstring=round_keys[x])
                wholevec = wholevec.__xor__(roundkey)
                # step 4: Inverse MixColumns 
                state = [[BitVector(intVal=int(wholevec.get_bitvector_in_hex()[i*8+j*2:i*8+j*2+2], 16), size=8) for j in range(4)] for i in range(4)]
                if (x != -1):
                    for i in range(4):
                        temp = (BitVector(bitstring='00001110').gf_multiply_modular(state[i][0], self.AES_modulus, 8)) ^ (BitVector(bitstring='00001011').gf_multiply_modular(state[i][1], self.AES_modulus, 8)) ^ (BitVector(bitstring='00001101').gf_multiply_modular(state[i][2], self.AES_modulus, 8)) ^ (BitVector(bitstring='00001001').gf_multiply_modular(state[i][3], self.AES_modulus, 8))
                        temp1 = (BitVector(bitstring='00001110').gf_multiply_modular(state[i][1], self.AES_modulus, 8)) ^ (BitVector(bitstring='00001011').gf_multiply_modular(state[i][2], self.AES_modulus, 8)) ^ (BitVector(bitstring='00001101').gf_multiply_modular(state[i][3], self.AES_modulus, 8)) ^ (BitVector(bitstring='00001001').gf_multiply_modular(state[i][0], self.AES_modulus, 8))
                        temp2 = (BitVector(bitstring='00001110').gf_multiply_modular(state[i][2], self.AES_modulus, 8)) ^ (BitVector(bitstring='00001011').gf_multiply_modular(state[i][3], self.AES_modulus, 8)) ^ (BitVector(bitstring='00001101').gf_multiply_modular(state[i][0], self.AES_modulus, 8)) ^ (BitVector(bitstring='00001001').gf_multiply_modular(state[i][1], self.AES_modulus, 8))
                        temp3 = (BitVector(bitstring='00001110').gf_multiply_modular(state[i][3], self.AES_modulus, 8)) ^ (BitVector(bitstring='00001011').gf_multiply_modular(state[i][0], self.AES_modulus, 8)) ^ (BitVector(bitstring='00001101').gf_multiply_modular(state[i][1], self.AES_modulus, 8)) ^ (BitVector(bitstring='00001001').gf_multiply_modular(state[i][2], self.AES_modulus, 8))

                        state[i][0] = temp
                        state[i][1] = temp1
                        state[i][2] = temp2
                        state[i][3] = temp3
                finalstring = ""
                for i in range(4):
                    for j in range(4):
                        finalstring += state[i][j].get_text_from_bitvector()
                decryptedtext += finalstring
                decrypted.write(decryptedtext)
        return

        

if __name__ == "__main__":
    cipher = AES(keyfile=sys.argv[3])
    if sys.argv[1] == "-e":
        cipher.encrypt(plaintext=sys.argv[2], ciphertext=sys.argv[4])
    elif sys.argv[1] == "-d":
        cipher.decrypt(ciphertext=sys.argv[2], decrypted=sys.argv[4])
    else:
        sys.exit("Incorrect Command-Line Syntax")
