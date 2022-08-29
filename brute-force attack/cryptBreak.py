# Homework Number: 01
# Name: Tingzhang Li
# ECN Login: li3402
# Due Date: 1/20/2022
#!/usr/bin/env python3
from BitVector import *

def cryptBreak(ciphertextFile, key_bv):
    # Arguments:
    # * ciphertextFile: String containing file name of the ciphertext
    # * key_bv: 16-bit BitVector for the decryption key
    #
    # Function Description:
    # Attempts to decrypt the ciphertext within ciphertextFile file using 
    # key_bv and returns the original plaintext as a string

    # The following code is based off of the program DecryptForFun.py provided by Professor Avi Kak in lecture 2
    BLOCKSIZE = 16
    byteLen = BLOCKSIZE // 8

    PassPhrase = "Hopes and dreams of a million years" #That's what EncryptForFun.py used, so decrypt use the same one

    initVec = BitVector(bitlist = [0]*BLOCKSIZE) 
    for i in range(0,len(PassPhrase) // byteLen):
        txt = PassPhrase[i*byteLen:(i+1)*byteLen]
        initVec ^= BitVector( textstring = txt )

    ciphertext = open(ciphertextFile)
    encryV = BitVector( hexstring = ciphertext.read() )

    decryV = BitVector( size = 0 )

    preDecryB = initVec
    for i in range(0, len(encryV) // BLOCKSIZE):
        bv = encryV[i*BLOCKSIZE:(i+1)*BLOCKSIZE]
        temp = bv.deep_copy()
        bv ^= preDecryB
        preDecryB = temp
        bv ^= key_bv
        decryV += bv
    return decryV.get_text_from_bitvector()


if __name__ == '__main__':
    for i in range(1, (2**16)):
        key_bv = BitVector(intVal = i, size = 16)
        decryptedText = cryptBreak('ciphertext.txt', key_bv)
        if ('Douglas Adams' in decryptedText):
            print("Message: " + decryptedText)
            print("Key is: " + str(i))
            break
        
