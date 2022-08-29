# Homework Number: 06
# Name: Tingzhang Li
# ECN Login: li3402
# Due Date: 3/03/2022

#!/usr/bin/env python3

import sys
from BitVector import *
from PrimeGenerator import *

# Global  constant
e = 65537


# This function was modified based on the code provided
# by Professor Avi Kak in lecture 5's code
def gcd(a, b):
    while b:
        a,b = b, a%b
    return a

# Get p and q
def generate():
    generator = PrimeGenerator(bits=128)
    flag = True
    msbSet = BitVector(bitstring = '11')
    while flag:
        p = generator.findPrime()
        q = generator.findPrime()
        p_bv = BitVector(intVal = p)
        q_bv = BitVector(intVal = q)
        # check (a) - two leftmost bits of p and q set?
        a = ((p_bv[0:2] == msbSet) and (q_bv[0:2] == msbSet))
        # check (b) - p=q?
        b = (p!=q) 
        # check (c) - (p−1) and (q−1)  co-prime to e?
        c = ((gcd(p-1, e)==1) and (gcd(q-1, e)==1))
        if (a and b and c):
            flag = False
    return p, q



# This function perform the encryption of RSA
def encrypt(message, pFile, qFile, encryptedFile):
    # read the input
    input_bv = BitVector(filename=message)  
    with open(pFile) as file:
        p = int(file.read().strip())
    with open(qFile) as file:
        q = int(file.read().strip())
    output = open(encryptedFile, 'w')

    # start encryption
    n = p*q # calculte the modulus
    while (input_bv.more_to_read):
        block_bv = input_bv.read_bits_from_file(128)
        if (block_bv.length()<128): # padding 0 to fill 128 bits
            block_bv.pad_from_right(128-block_bv.length())
        block_bv.pad_from_left(128) # padding to left to make 256 bits
        value = pow(int(block_bv), e, n)
        output_bv = BitVector(intVal=value)
        output_bv.pad_from_left(256 - output_bv.length())
        hex_str = output_bv.get_bitvector_in_hex()
        output.write(hex_str)
    output.close()
    return


# This function perform the decryption of RSA
def decrypt(encryptedFile, pFile, qFile, decryptedFile):
    # read the input
    with open(encryptedFile) as file:
        input_hex = file.read().strip() 
    input_bv = BitVector(hexstring = input_hex)
    with open(pFile) as file:
        p = int(file.read().strip())
    with open(qFile) as file:
        q = int(file.read().strip())

    # get some value and bv for chinese reminder theorem
    # refernce: lecture 11 and lecture 12 note 
    totient = (p-1)*(q-1)
    totient_bv = BitVector(intVal=totient)    
    e_bv = BitVector(intVal=e)
    d_bv = e_bv.multiplicative_inverse(totient_bv)
    d = d_bv.int_val()
    n = p*q 
    p_bv = BitVector(intVal=p)
    q_bv = BitVector(intVal=q)
    p_mi = p_bv.multiplicative_inverse(q_bv)
    q_mi = q_bv.multiplicative_inverse(p_bv)
    xp = q*q_mi.int_val()
    xq = p*p_mi.int_val()

    # start decreption
    output_bv = BitVector(size=0)
    block=0
    while (block < (len(input_bv)//256)):
        block_bv = input_bv[(block*256):((block+1)*256)]
        block_value = block_bv.int_val()
        # apply chinese reminder theorem
        vp = pow(block_value, d, p)
        vq = pow(block_value, d, q)
        decrypted = (vp*xp + vq*xq) % n
        decrypted_bv = BitVector(intVal=decrypted, size=128)
        output_bv += decrypted_bv
        block += 1    
    output = open(decryptedFile, 'wb')
    output_bv.write_to_file(output)
    output.close()
    return

if __name__ == '__main__':
    if sys.argv[1] == '-g':  # generate
        if len( sys.argv ) != 4:                                                 
            sys.exit( "Need 3 arguments" )
        pFile = sys.argv[2]
        qFile = sys.argv[3]
        p,q = generate()
        with open(pFile, 'w') as file:
            file.write(str(p))
        with open(qFile, 'w') as file:
            file.write(str(q))
    elif sys.argv[1] == '-e':  # encryption
        if len( sys.argv ) != 6:                                                 
            sys.exit( "Need 5 arguments" )
        encrypt(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    elif sys.argv[1] == '-d':  # decryption
        if len( sys.argv ) != 6:                                                 
            sys.exit( "Need 5 arguments" )
        decrypt(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    else:
        sys.exit("First argument need to be -g or -e or -d") 