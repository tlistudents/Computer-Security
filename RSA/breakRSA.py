# Homework Number: 06
# Name: Tingzhang Li
# ECN Login: li3402
# Due Date: 3/03/2022

#!/usr/bin/env python3


import sys
from BitVector import *
from PrimeGenerator import *
import numpy as np

# Global  constant
e = 3

"""
First, re-used and modified the function created for problem 1
to generate key and encryption, those functions
"""
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
def encrypt(message, p, q, encryptedFile):
    # read the input
    input_bv = BitVector(filename=message)  
    #with open(pFile) as file:
    #    p = int(file.read().strip())
    #with open(qFile) as file:
    #    q = int(file.read().strip())
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


"""
The following codes are new for this problem 
"""

# This function is provided by Professor Avi Kak in homework 6
'''
Finds pth root of an integer x.  Uses Binary Search logic.  Start with a lower
bound l and go up until upper bound u.  Break the problem into halves depending
on the search logic.  The search logic says whether the mid (which is the mid
value of l and u) raised to the power to p is less than x or it is greater than
x.  Once we reach a mid that when raised to the power p is equal to x, we
return mid + 1. 

Author: Shayan Akbar
	sakbar at purdue edu

'''
def solve_pRoot(p, x): #O(lgn) solution

    #Upper bound u is set to as follows:
    #We start with the 2**0 and keep increasing the power so that u is 2**1, 2**2, ...
    #Until we hit a u such that u**p is > x
    u = 1
    while u ** p <= x: u *= 2

    #Lower bound set to half of upper bound
    l = u // 2

    #Keep the search going until upper u becomes less than lower l
    while l < u:
        mid = (l + u) // 2
        mid_pth = mid ** p
        if l < mid and mid_pth < x:
            l = mid
        elif u > mid and mid_pth > x:
            u = mid
        else:
            # Found perfect pth root.
            return mid
    return mid + 1


# This function encrypt same message 3 times using different 
# key(step 1 and 2)
def encrypt3(message, enc1, enc2, enc3, n_1_2_3):
    output = open(n_1_2_3, 'w')

    p1, q1 = generate()
    n1 = p1*q1
    encrypt(message, p1, q1, enc1)
    output.write(str(n1))
    output.write('\n')

    p2, q2 = generate()
    n2 = p2*q2
    encrypt(message, p2, q2, enc2)
    output.write(str(n2))
    output.write('\n')

    p3, q3 = generate()
    n3 = p3*q3
    encrypt(message, p3, q3, enc3)
    output.write(str(n3))
    output.close()
    return


# This function break RSA encryption
def crack(enc1, enc2, enc3, n_1_2_3, cracked):
    # get the encreypted message and keys from input
    with open(n_1_2_3) as file:
        n1 = int(file.readline().strip())
        n2 = int(file.readline().strip())
        n3 = int(file.readline().strip())
    with open(enc1) as file1:
        hex = file1.read().strip()
        enc_bv1 = BitVector(hexstring=hex) 
    with open(enc2) as file2:
        hex = file2.read().strip()
        enc_bv2 = BitVector(hexstring=hex)   
    with open(enc3) as file3:
        hex = file3.read().strip()
        enc_bv3 = BitVector(hexstring=hex)   

    # calcualte some values for breaking, as descributed in lecture 12 note
    n_big_all = n1*n2*n3
    n_big_1 = n2 * n3
    n_big_1_bv = BitVector(intVal=n_big_1)
    n_big_2 = n1 * n3
    n_big_2_bv = BitVector(intVal=n_big_2)
    n_big_3 = n1 * n2
    n_big_3_bv = BitVector(intVal=n_big_3)
    n_big1_inv = int(n_big_1_bv.multiplicative_inverse(BitVector(intVal=n1)))
    n_big2_inv = int(n_big_2_bv.multiplicative_inverse(BitVector(intVal=n2)))
    n_big3_inv = int(n_big_3_bv.multiplicative_inverse(BitVector(intVal=n3)))

    # start breaking, reference: lecture 12 notes
    output_bv = BitVector(size=0)
    for block in range(0, enc_bv1.length(), 256):
        cipher1 = int(enc_bv1[block: block+256])
        cipher2 = int(enc_bv2[block: block+256])
        cipher3 = int(enc_bv3[block: block+256])
        crt = cipher1*n_big_1*n_big1_inv + cipher2*n_big_2*n_big2_inv + cipher3*n_big_3*n_big3_inv
        crt %= n_big_all
        decrypted = solve_pRoot(3, crt)
        output_bv += BitVector(intVal=decrypted, size=128)
    with open(cracked, 'wb') as file4:
        output_bv.write_to_file(file4)
    return



if __name__ == '__main__':
    if sys.argv[1] == '-e':  # encrypte
        if len( sys.argv ) != 7:                                                 
            sys.exit( "Need 6 arguments" )
        encrypt3(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5],sys.argv[6])
    elif sys.argv[1] == '-c':  # crack
        if len( sys.argv ) != 7:                                                 
            sys.exit( "Need 6 arguments" )
        crack(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5],sys.argv[6])
    else:
        sys.exit("First argument need to be -e or -c") 