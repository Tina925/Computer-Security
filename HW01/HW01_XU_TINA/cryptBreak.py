'''
Homework Number: 1
Name: Tina Xu 
ECN Login: xu1493
Due Date: 01/18/2023 
'''

from BitVector import *

def cryptBreak (ciphertextFile, key_bv):
 # Arguments :
 # * ciphertextFile : String containing file name of the  ciphertext
 # * key_bv : 16 -bit BitVector for the decryption key
    file = open(ciphertextFile,"r")
    encrypted_bv = BitVector(hexstring = file.read())
    
    #below code are cited from lecture 2 (p51-p52)
    PassPhrase = "Hopes and dreams of a million years" 
    BLOCKSIZE = 16 
    numbytes = BLOCKSIZE // 8 
    # Reduce the passphrase to a bit array of size BLOCKSIZE:
    bv_iv = BitVector(bitlist = [0]*BLOCKSIZE) 
    for i in range(0,len(PassPhrase) // numbytes): 
        textstr = PassPhrase[i*numbytes:(i+1)*numbytes] 
        bv_iv ^= BitVector( textstring = textstr )
    # Create a bitvector for storing the decrypted plaintext bit array:
    msg_decrypted_bv = BitVector(size = 0)
    # Carry out differential XORing of bit blocks and decryption:
    previous_decrypted_block = bv_iv  
    
    for i in range(0, len(encrypted_bv) // BLOCKSIZE): 
        bv = encrypted_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE] 
        temp = bv.deep_copy()
        bv ^= previous_decrypted_block 
        previous_decrypted_block = temp 
        bv ^= key_bv 
        msg_decrypted_bv += bv 
    # Extract plaintext from the decrypted bitvector:
    outputtext = msg_decrypted_bv.get_text_from_bitvector()
    
    return outputtext

if __name__ == "__main__":
    for x in range(0,2**16):
        key_bv = BitVector(intVal = x, size =16)
        decryptedMessage = cryptBreak('cipherText.txt', key_bv)
        if "Ferrari" in decryptedMessage:
            print(x)
            FILE = open("output.txt","w")
            FILE.write(decryptedMessage)
            break
