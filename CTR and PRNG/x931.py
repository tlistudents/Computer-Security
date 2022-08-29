# Homework Number: 05
# Name: Tingzhang Li
# ECN Login: li3402
# Due Date: 2/22/2022

#!/usr/bin/env python3
import sys
from BitVector import *


#The following part are my AES implementation from hw4
"""
The following code is provided by Professor Avinash Kak in Lecture 8 code
"""
AES_modulus = BitVector(bitstring='100011011')

# For Byte Substitution Step
def genTables():
    subBytesTable = [] # for encryption
    invSubBytesTable = []    # for decryption
    c = BitVector(bitstring='01100011')
    d = BitVector(bitstring='00000101')
    for i in range(0, 256):
        # For the encryption SBox
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
        # For the decryption Sbox:
        b = BitVector(intVal = i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1,b2,b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        invSubBytesTable.append(int(b))
    return subBytesTable, invSubBytesTable

def gee(keyword, round_constant, byte_sub_table):
    '''
    This is the g() function you see in Figure 4 of Lecture 8.
    '''
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size = 0)
    for i in range(4):
        newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8)
    return newword, round_constant

def gen_key_schedule_256(key_bv):
    byte_sub_table = gen_subbytes_table()
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
            kwd, round_constant = gee(key_words[i-1], round_constant, byte_sub_table)
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

def gen_subbytes_table():
    subBytesTable = []
    c = BitVector(bitstring='01100011')
    for i in range(0, 256):
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
    return subBytesTable
"""
The above code is provided by Professor Avinash Kak in Lecture 8 code
"""

# Shift Row Step:
def LeftShiftOne(arr): # Shift a row to left by one
    a = arr[0]
    for i in range(3):
        arr[i] = arr [i+1]
    arr[3] = a
    return arr
def ShiftRows(statearray): 
    for i in range(1,4):
        index = 0
        while(index<i):
            arr = [statearray[0][i],statearray[1][i],statearray[2][i],statearray[3][i]] 
            statearray[0][i],statearray[1][i],statearray[2][i],statearray[3][i] = LeftShiftOne(arr)
            index+=1
    return statearray
            
def RightShiftOne(arr): # Shift a row to right by one
    a = arr[3]
    for i in range(3):
        arr[3-i] = arr [2-i]
    arr[0] = a
    return arr
def InvShiftRows(statearray):
    for i in range(1,4):
        index = 0
        while(index<i):
            arr = [statearray[0][i],statearray[1][i],statearray[2][i],statearray[3][i]]
            statearray[0][i],statearray[1][i],statearray[2][i],statearray[3][i] = RightShiftOne(arr)
            index+=1
    return statearray


# Mix Columns Step:
def MixColumns(statearray):
    output = [[0 for x in range(4)] for x in range(4)] # from Professor Avinash Kak
    bv_2 = BitVector(bitstring = '00000010')
    bv_3 = BitVector(bitstring = '00000011')
    # Follow Lecture 8 Note to do a seriers of multiplcation and xor
    for j in range(4):
        # first row
        s0jx2 = statearray[j][0].gf_multiply_modular(bv_2, AES_modulus,8)
        s1jx03 = statearray[j][1].gf_multiply_modular(bv_3, AES_modulus,8)
        output[j][0] = s0jx2 ^ s1jx03 ^ statearray[j][2] ^ statearray[j][3]
        # second row
        sj1x2 = statearray[j][1].gf_multiply_modular(bv_2, AES_modulus,8)
        sj2x3 = statearray[j][2].gf_multiply_modular(bv_3, AES_modulus,8)
        output[j][1] = statearray[j][0] ^ sj1x2 ^ sj2x3 ^ statearray[j][3]
        # third row
        sj2x2 = statearray[j][2].gf_multiply_modular(bv_2, AES_modulus,8)
        sj3x3 = statearray[j][3].gf_multiply_modular(bv_3, AES_modulus,8)
        output[j][2] = statearray[j][0] ^ statearray[j][1] ^ sj2x2 ^ sj3x3
        # fourth row
        sj0x3 = statearray[j][0].gf_multiply_modular(bv_3, AES_modulus,8)
        sj3x2 = statearray[j][3].gf_multiply_modular(bv_2, AES_modulus,8)
        output[j][3] = sj0x3 ^ statearray[j][1] ^ statearray[j][2] ^ sj3x2
    return output   

def InvMixColumns(statearray):
    output = [[0 for x in range(4)] for x in range(4)]
    bv_B = BitVector(bitstring='00001011')
    bv_D = BitVector(bitstring='00001101')
    bv_E = BitVector(bitstring='00001110')
    bv_9 = BitVector(bitstring='00001001')
    # Follow Lecture 8 Note to do a seriers of multiplcation and xor(matrix mutimplcation)
    # xor(^) is +, arr.gf_multiply_modular(bv, AES_modulus,8) is *
    for j in range(4):
        # first row
        col00 = statearray[j][0].gf_multiply_modular(bv_E, AES_modulus,8)
        col01 = statearray[j][1].gf_multiply_modular(bv_B, AES_modulus,8)
        col02 = statearray[j][2].gf_multiply_modular(bv_D, AES_modulus,8)
        col03 = statearray[j][3].gf_multiply_modular(bv_9, AES_modulus,8)
        output[j][0] = col00 ^ col01 ^ col02 ^ col03
        # second row
        col10 = statearray[j][1].gf_multiply_modular(bv_E, AES_modulus,8)
        col11 = statearray[j][2].gf_multiply_modular(bv_B, AES_modulus,8)
        col12 = statearray[j][3].gf_multiply_modular(bv_D, AES_modulus,8)
        col13 = statearray[j][0].gf_multiply_modular(bv_9, AES_modulus,8)
        output[j][1] = col10 ^ col11 ^ col12 ^ col13
        # third row
        col20 = statearray[j][2].gf_multiply_modular(bv_E, AES_modulus,8)
        col21 = statearray[j][3].gf_multiply_modular(bv_B, AES_modulus,8)
        col22 = statearray[j][0].gf_multiply_modular(bv_D, AES_modulus,8)
        col23 = statearray[j][1].gf_multiply_modular(bv_9, AES_modulus,8)
        output[j][2] = col20 ^ col21 ^ col22 ^ col23
       # fourth row
        col30 = statearray[j][3].gf_multiply_modular(bv_E, AES_modulus,8)
        col31 = statearray[j][0].gf_multiply_modular(bv_B, AES_modulus,8)
        col32 = statearray[j][1].gf_multiply_modular(bv_D, AES_modulus,8)
        col33 = statearray[j][2].gf_multiply_modular(bv_9, AES_modulus,8)
        output[j][3] = col30 ^ col31 ^ col32 ^ col33
    return output   


"""
The overall structure and part of the code below is provided by
Professor Avinash Kak in Lecture 3 code(demonstration code for DES)
as well as in Lecture 8 code(in gen_key_schedule.py)
"""
# Encryption:
def encrypt(inputMes,key):
    output=BitVector(size=0) 
    # Turn input into bv
    key1 = open(key,"r")
    key_bv = BitVector(textstring=key1.read())
    intput_bv = inputMes

    # Get some parameters, codes are modified from Lecture 8 code provided by Professor Avinash Kak
    round_keys = [None for i in range(15)]
    key_words = gen_key_schedule_256(key_bv)
    for i in range(15):
        round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + key_words[i*4+3])
    subBytesTable, invSubBytesTable = genTables()
    statearray = [[0 for x in range(4)] for x in range(4)] # from Professor Avinash Kak

    # Start encryption
    # hh=0 was used for debug
    #output = open(outputEncry, "w")
    #while(intput_bv.more_to_read):
    #    block_bv = intput_bv.read_bits_from_file( 128 )
    #    if (block_bv.length()<128): # padding 0
    #        block_bv.pad_from_right(128-block_bv.length())  
    s=0
    block_num = len(intput_bv)//128
    for x in range(block_num):
        block_bv = intput_bv[s:s+128]
        s += 128   
        # first round
        block_bv ^= round_keys[0] # xor with the keys

        # 256 key size: 14 rounds
        for round in range(14):
            # Step 1: SubBytes
            # codes are modified from Lecture 3 code provided by Professor Avinash Kak(hw2_starter.py)
            for i in range(16): 
                L,R = block_bv[i*8:(i*8+8)].divide_into_two()
                tableIndex = int(L)*16 + int(R)
                block_bv[i*8:(i*8+8)] = BitVector(intVal=subBytesTable[tableIndex], size=8)
            # replace state array using table
            index = 0
            statearray, index = UpdateStateArray(block_bv, statearray, index)

            # Step 2: ShiftRows    
            statearray = ShiftRows(statearray)
            
            # Step 3: MixColumns
            if(round != 13): # don't mix in last round
                statearray = MixColumns(statearray)
            
            # Step 4: AddRoundKey
            block_bv, index = UpdateBlockBV(statearray, index)
            block_bv ^= round_keys[round+1]
            # check if the block matches first_round_aes.txt
            #if(hh==0): 
            #    hh +=1
            #    print(block_bv)
        output += block_bv
        #output.write(hexstring) # Write to hex
    key1.close()
    #output.close()
    return output

# Decryption
def decrypt(inputMes,key,outputDecry):
    # Turn input into bv
    input = open(inputMes,"r")
    intput_bv = BitVector(hexstring = input.read())
    key1 = open(key,"r")
    key_bv = BitVector(textstring=key1.read())

    # Get some parameters, codes are modified from Lecture 8 code provided by Professor Avinash Kak
    round_keys = [None for i in range(15)]
    key_words = gen_key_schedule_256(key_bv)
    for i in range(15):
        round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + key_words[i*4+3])

    subBytesTable, invSubBytesTable = genTables()
    statearray = [[0 for x in range(4)] for x in range(4)] # from Professor Avinash Kak
    
    # Start encryption
    b_index = 0
    output = open(outputDecry, "wb")
    num_block = intput_bv.length()//128  # manually read 128 bit for each block
    stop = 0

    round_keys.reverse() # need to go from backward for decrypto
    while (stop < num_block):
        stop += 1
        block_bv = intput_bv[b_index:b_index+128]
        b_index += 128

        # first round 
        block_bv ^= round_keys[0] # xor with the keys
        # 256 key size: 14 rounds
        for round in range(14):
            index = 0
            # state array update
            statearray, index = UpdateStateArray(block_bv, statearray, index)
        
            # Step 1: InvShiftRows
            statearray = InvShiftRows(statearray)

            # Step 2: InvSubBytes
            for i in range(4):
                for j in range(4):
                    tableIndex = int(statearray[i][j])
                    statearray[i][j] = BitVector(intVal=invSubBytesTable[tableIndex],size=8)
            
            # Step 3: AddRoundKey
            block_bv, index = UpdateBlockBV(statearray, index)
            block_bv ^= round_keys[round+1]

            # Step 4: InvMixColumns
            index = 0
            statearray, index = UpdateStateArray(block_bv, statearray, index) 
            if(round != 13): # last round don't mix
                statearray = InvMixColumns(statearray)

            block_bv, index = UpdateBlockBV(statearray, index)

        block_bv.write_to_file(output) #write output
    key1.close()
    output.close()
    return 1

# Helper function to exchange statearray and block bit vector
def UpdateStateArray(block_bv, statearray, index):
    for i in range(4):
        for j in range(4):
            statearray[i][j] = block_bv[index:index+8]
            index += 8
    return statearray, index

def UpdateBlockBV(statearray, index):
    block_bv = BitVector(size = 0)
    for i in range(4):
        for j in range(4):
            block_bv += statearray[i][j]
            index += 8
    return block_bv, index

#The above part are my AES implementation from hw4
#----------------------------------------------------------------


# The following part are new for hw5
'''
* Arguments:
    v0: 128-bit BitVector object containing the seed value
    dt: 128-bit BitVector object symbolizing the date and time
    totalNum: The total number of random numbers to generate
    key_file: Filename for text file containing the ASCII encryption key for AES

* Function Description:
This function uses the arguments with the X9.31 algorithm to generate totalNum
    random numbers as BitVector objects.
Returns a list of BitVector objects, with each BitVector object representing a
    random number generated from X9.31.
'''
def x931(v0, dt, totalNum, key_file):
    rand_num = list()
    vj = v0
    dt_EDE = encrypt(dt,key_file)
    for i in range(0,totalNum):
        vj_dt_xor = vj ^ dt_EDE
        rj = encrypt(vj_dt_xor,key_file)
        rand_num.append(rj)
        rj_dt_EDE = rj ^ dt_EDE
        vj = encrypt(rj_dt_EDE,key_file)
    return rand_num 