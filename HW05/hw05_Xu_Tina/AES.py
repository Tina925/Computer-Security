'''
Homework Number: 5
Name: Tina Xu 
ECN Login: xu1493
Due Date: 02/20/2023 
'''
import sys
from BitVector import *

class AES:
    #The function genTables, gee, gen_key_schedule_256, gen_subbytes_table, get_key_from_user, are all from Lecture Notes 8. 
    
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
        key_bv = BitVector( textstring = key)
        return keysize,key_bv
    
    def encrypt(self, plaintext: BitVector, round_keys: list[BitVector]) -> BitVector:
        #print("hello")
        state = [[0 for x in range(4)] for x in range(4)]
        # xor
        bv = plaintext
        bv = bv.__xor__(round_keys[0])
        state = [[bv[i*32+j*8:i*32+j*8+8] for j in range(4)] for i in range(4)]
        for x in range(1, 15):
            # Step 1: SubBytes
            for i in range(4):
                for j in range(4):
                    state[i][j] = BitVector(intVal=self.subBytesTable[int(state[i][j])], size=8)

            # Step 2: ShiftRows
            shift = [0] * 4
            for row in range(1, 4):       
                for col in range(0, 4):
                    shift[col] = state[(col + row) % 4][row]
                for col in range(0, 4):
                    state[col][row] = shift[col]
            # Step 3: MixColumns 
            
            if (x != 14):
                newArray = [[0 for x in range(4)] for x in range(4)]
                for i in range(4):
                    newArray[i][0] = (BitVector(bitstring='00000010').gf_multiply_modular(state[i][0], self.AES_modulus, 8)) ^ (BitVector(bitstring='00000011').gf_multiply_modular(state[i][1], self.AES_modulus, 8)) ^ state[i][2] ^ state[i][3]
                    newArray[i][1] = (BitVector(bitstring='00000010').gf_multiply_modular(state[i][1], self.AES_modulus, 8)) ^ (BitVector(bitstring='00000011').gf_multiply_modular(state[i][2], self.AES_modulus, 8)) ^ state[i][3] ^ state[i][0]
                    newArray[i][2] = (BitVector(bitstring='00000010').gf_multiply_modular(state[i][2], self.AES_modulus, 8)) ^ (BitVector(bitstring='00000011').gf_multiply_modular(state[i][3], self.AES_modulus, 8)) ^ state[i][0] ^ state[i][1]
                    newArray[i][3] = (BitVector(bitstring='00000010').gf_multiply_modular(state[i][3], self.AES_modulus, 8)) ^ (BitVector(bitstring='00000011').gf_multiply_modular(state[i][0], self.AES_modulus, 8)) ^ state[i][1] ^ state[i][2]
                state = newArray
            # Step 4: AddRoundKey
            finalhex = ""
            for i in range(4):
                for j in range(4):
                    finalhex += state[i][j].get_bitvector_in_hex()
            finalvec = BitVector(hexstring = finalhex)
            finalvec = finalvec.__xor__(round_keys[x])
            
            for i in range(4):
                for j in range(4):
                    state[i][j] = finalvec[i*32+j*8:i*32+j*8+8] 
        final = ""
        for i in range(4):
            for j in range(4):
                final += state[i][j].get_bitvector_in_hex()
        ciphertext = BitVector(hexstring = final)
        return ciphertext
            #file.write(final.get_bitvector_in_hex())
        #pass
    
    def decrypt(self, ciphertext: str, decrypted: str) -> None:
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
            round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + key_words[i*4+3])
        file = open(ciphertext, "r")
        bve = BitVector(hexstring = file.read())
        fileout = open(decrypted, "w")
        state = [[0 for x in range(4)] for x in range(4)]
  
        for i in range(0, len(bve) // 128):
            bitvec = bve[slice(i * 128, (i + 1) * 128)]
            #XOR 
            bitvec = bitvec.__xor__(round_keys[14])
            state = [[bitvec[i*32+j*8:i*32+j*8+8] for i in range(4)] for j in range(4)]
         
            for x in range(1, 15):
                #Inverse shift rows
                for i in range(1, 4):
                    state[i] = state[i][-i:] + state[i][:-i]
                #inverse byte sub
                for i in range(4):
                    for j in range(4):
                        state[i][j] = BitVector(intVal=self.invSubBytesTable[int(state[i][j])], size=8)
    
                #Add round key
                finalhex = ""
                for i in range(4):
                    for j in range(4):
                        finalhex += state[j][i].get_bitvector_in_hex()
                finalvec = BitVector(hexstring=finalhex)
                finalvec = finalvec.__xor__(round_keys[14 - x])
                for i in range(4):
                    for j in range(4):
                        state[j][i] = finalvec[i*32+j*8:i*32+j*8+8] 

                #Inverse mix columns
                if x != 14:
                    newArray = [[0 for x in range(4)] for x in range(4)]
                    for i in range(4):
                        newArray[0][i] = (state[0][i].gf_multiply_modular(BitVector(intVal = 0x0E, size = 8),self.AES_modulus,8))^(state[1][i].gf_multiply_modular(BitVector(intVal = 0x0B, size = 8),self.AES_modulus,8))^(state[2][i].gf_multiply_modular(BitVector(intVal = 0x0D, size = 8),self.AES_modulus,8))^(state[3][i].gf_multiply_modular(BitVector(intVal = 0x09, size = 8),self.AES_modulus,8))
                        newArray[1][i] = (state[0][i].gf_multiply_modular(BitVector(intVal = 0x09, size = 8),self.AES_modulus,8))^(state[1][i].gf_multiply_modular(BitVector(intVal = 0x0E, size = 8),self.AES_modulus,8))^(state[2][i].gf_multiply_modular(BitVector(intVal = 0x0B, size = 8),self.AES_modulus,8))^(state[3][i].gf_multiply_modular(BitVector(intVal = 0x0D, size = 8),self.AES_modulus,8))
                        newArray[2][i] = (state[0][i].gf_multiply_modular(BitVector(intVal = 0x0D, size = 8),self.AES_modulus,8))^(state[1][i].gf_multiply_modular(BitVector(intVal = 0x09, size = 8),self.AES_modulus,8))^(state[2][i].gf_multiply_modular(BitVector(intVal = 0x0E, size = 8),self.AES_modulus,8))^(state[3][i].gf_multiply_modular(BitVector(intVal = 0x0B, size = 8),self.AES_modulus,8))
                        newArray[3][i] = (state[0][i].gf_multiply_modular(BitVector(intVal = 0x0B, size = 8),self.AES_modulus,8))^(state[1][i].gf_multiply_modular(BitVector(intVal = 0x0D, size = 8),self.AES_modulus,8))^(state[2][i].gf_multiply_modular(BitVector(intVal = 0x09, size = 8),self.AES_modulus,8))^(state[3][i].gf_multiply_modular(BitVector(intVal = 0x0E, size = 8),self.AES_modulus,8))
                    state = newArray
            #Write
            output = ""
            for i in range(4):
                for j in range(4):
                    output += (state[j][i]).get_bitvector_in_ascii()
            fileout.write(output)
        pass

    def ctr_aes_image(self, iv, image_file, enc_image):
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
            round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + key_words[i*4+3])
    
        inputs = open(image_file, "rb")
        output = open(enc_image, "wb")
        for x in range(3):
            output.write(inputs.readline())
        bv = BitVector(rawbytes = inputs.read())
        if (len(bv) % 128 != 0):
            zero = 128 - len(bv) % 128
            bv.pad_from_right(zero)
        for i in range(0, len(bv) // 128):
            bitvec = bv[slice(i * 128, (i + 1) * 128)]
            cipherbit = self.encrypt(iv, round_keys)
            cipherbit = cipherbit.__xor__(bitvec)
            iv_int = iv.intValue()
            iv = BitVector(intVal = iv_int+1, size=128)
            out = cipherbit
            out.write_to_file(output)
        pass

    def x931 (self, v0, dt, totalNum, outfile):
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
            round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + key_words[i*4+3])
        
        output = open(outfile, "w")
        vt= v0
        for i in range(totalNum):
            #equation 1
            vt2 = self.encrypt(dt, round_keys)
            vt = vt2.__xor__(vt)
            rj = self.encrypt(vt, round_keys)
            output.write(str(rj.intValue()) + '\n')
            #equation 2
            newvt = rj.__xor__(vt2)
            vt = self.encrypt(newvt, round_keys)
        pass


if __name__ == "__main__":
    cipher = AES(keyfile=sys.argv[3])
    if sys.argv[1] == "-e":
        cipher.encrypt(plaintext=sys.argv[2], ciphertext=sys.argv[4])
    elif sys.argv[1] == "-d":
        cipher.decrypt(ciphertext=sys.argv[2], decrypted=sys.argv[4])
    elif sys.argv [1] == "-i":
        cipher.ctr_aes_image(iv= BitVector(textstring ="counter-mode-ctr"),
        image_file =sys.argv[2],
        enc_image =sys.argv[4])
    else: 
        cipher.x931 (v0= BitVector(textstring ="counter-mode-ctr"),
                      dt= BitVector(intVal=501, size=128), totalNum=
                      int(sys.argv[2]), outfile=sys.argv[4])
