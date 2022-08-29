import cryptBreak
from BitVector import *

#someRandomInteger = 29556 #Arbitrary integer for creating a BitVector
#key_bv = BitVector(intVal=someRandomInteger, size=16)
#decryptedMessage = cryptBreak.cryptBreak('ciphertext.txt', key_bv)
#if 'Douglas Adams' in decryptedMessage:
#    print('Encryption Broken!')
#    print(decryptedMessage)
#else:
#    print('Not decrypted yet')
#
for i in range(1, (2**16)):
    key_bv = BitVector(intVal = i, size = 16)
    decryptedText = cryptBreak.cryptBreak('ciphertext.txt', key_bv)
    if ('Douglas Adams' in decryptedText):
        print("Message: " + decryptedText)
        print("Key is: " + str(i))
        break