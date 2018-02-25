from Crypto.Util.number import getPrime
import sys
sys.path.append('../')

from utils import *
from cbc import *
from sha1 import SHA1
import math

                      
class RSA(object):

    def __init__(self, keysize):
        '''
        keysize is in bytes
        '''
        self.keysize= keysize
        self.e = 3 # public

        # private
        self.p, self.q = getPrime(self.keysize//2),getPrime(self.keysize//2)
        
        # public (cannot deduce p and q from n)
        # that's where the security lies
        self.n = self.p*self.q

        phi = (self.p-1)*(self.q-1)        
        while gcd(self.e, phi) != 1:
            self.p, self.q = getPrime(self.keysize//2),getPrime(self.keysize//2)
            phi = (self.p-1)*(self.q-1)
            self.n = self.p * self.q


        self.d = modular_inverse(self.e, phi) # private

    def encrypt(self, m):

        # bytes_to_int(m)
        return pow(m, self.e, self.n)

    def decrypt(self, m):

        return pow(m, self.d, self.n)
        

def int_to_bytes(n):
    """Converts the given int n to bytes and returns them."""
    return [i for i in n.to_bytes((n.bit_length() + 7) // 8, 'big')]

if __name__ == '__main__':

    R = RSA(1024)

    msg = string_to_list('Leighton Baines plays for Everton')    
    msg_int = bytes_to_int(msg)
    
    x = R.encrypt(msg_int)
    y = R.decrypt(x)
    print(list_to_string(int_to_bytes(y)))
