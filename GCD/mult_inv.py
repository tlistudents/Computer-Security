# Homework Number: 03
# Name: Tingzhang Li
# ECN Login: li3402
# Due Date: 02/02/2022

#!/usr/bin/env python3

import sys

"""
This code was inspired by the algorithm described in:
https://github.com/DavidNorman/gcd
This code is revised based on BGCD.py and FindMI.py provided by 
Professor Avinash Kak as well as the algorithm that I used as 
referenced 
"""

# ~a & 1 - check even
# a & 1 - check odd
# a >> 1 divide 2
# a << 1 mul 2

def DivTwo(num):
    if(~num & 1):
        return(num>>1)
    else:
        return((num-1)>>1)

def MUL(a, b):
    if(b == 1): return a
    if(b == 0): return 0
    tem = a
    while(b > 1):
        a += tem
        b -= 1
    return a

# This function use the algorithm from the reference link as base
# Modified from BGCD.py and FindMI.py provided by Professor Avinash Kak
def BFindMI(a,b):
    sx, sy, tx, ty = 1, 0, 0, 1
    c = 0
    while (~a & 1) and (~b & 1):
        a = DivTwo(a)
        b = DivTwo(b)
        c += 1
    rx, ry = a, b

    while (~a & 1):
        a = DivTwo(a)
        if (~sx & 1) and (~sy & 1):
            sx = DivTwo(sx)
            sy = DivTwo(sy)
        else:
            sx = DivTwo(sx+ry)
            sy = DivTwo(sy-rx)
    while a != b:
        if (~b & 1):
            b = DivTwo(b)
            if (~tx & 1) and (~ty & 1):
                tx = DivTwo(tx)
                ty = DivTwo(ty)
            else:
                tx = DivTwo(tx+ry)
                ty = DivTwo(ty-rx)
        elif b < a: # modified based on the input number
                a, b, sx, sy, tx, ty = b, a, tx, ty, sx, sy
        else:
            b, tx, ty = b - a, tx - sx, ty - sy
    if(c == 0): # 2^0 is 1
        return a, tx
    else: 
        return MUL((2 << (c-1)), a), tx


if len(sys.argv) != 3:
    sys.exit("\nUsage:   %s  <integer>  <integer>\n" % sys.argv[0])

a,b = int(sys.argv[1]),int(sys.argv[2])

gcdval, mi = BFindMI(a, b)

# The following print statement is provided by Professor Avinash Kak in FindMI.pu
if gcdval != 1:
    print("\nNO MI. However, the GCD of %d and %d is %u\n" % (a, b, gcdval))
else:
    print("\nMI of %d modulo %d is: %d\n" % (a, b, mi))