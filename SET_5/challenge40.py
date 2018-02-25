from Crypto.Util.number import getPrime
import sys
sys.path.append('../')

from utils import *


from challenge39 import RSA, modular_inverse

'''
For this to work m**e has to be smaller than n1*n2...nk
but as they set e=3

the small exponent attack works
'''
# Stolen from that GEEKS for GEEKS website
# k is size of num[] and rem[]. 

# Returns the smallest
# number x such that:
# x % num[0] = rem[0],
# x % num[1] = rem[1],
# ..................
# x % num[k-1] = rem[k-1]
# Assumption: Numbers in num[] 
# are pairwise coprime
# (gcd for every pair is 1)
def findMinX(num, rem, k) :
     
    # Compute product of all numbers
    prod = 1
    for i in range(0, k) :
        prod = prod * num[i]
 
    # Initialize result
    result = 0
 
    # Apply above formula
    for i in range(0,k):
        pp = prod // num[i]
        result = result + rem[i] * modular_inverse(pp, num[i]) * pp
     
     
    return result % prod

def find_cube_root(n):
    
    """Finds the cube root of n using binary search."""
    lo = 0
    hi = n

    while lo < hi:
        mid = (lo + hi) // 2
        if mid**3 < n:
            lo = mid + 1
        else:
            hi = mid

    return lo

def int_to_bytes(n):
    """Converts the given int n to bytes and returns them."""
    return [i for i in n.to_bytes((n.bit_length() + 7) // 8, 'big')]

if __name__ == '__main__':



    ciphers = []
    mods = []
    for i in range(3):
        
        R = RSA(1024)
        msg = string_to_list('Leighton Baines plays for Everton')    
        msg_int = bytes_to_int(msg)

        ciphers.append(R.encrypt(msg_int))
        mods.append(R.n)

    # Finding X according to CRT
    answer = findMinX(mods, ciphers, len(ciphers))

    # Cubing it 
    print("MESSAGE : ", list_to_string(int_to_bytes(find_cube_root(answer))))

