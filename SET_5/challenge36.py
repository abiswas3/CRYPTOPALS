import sys
sys.path.append('../')

from utils import *
from cbc import *
from sha1 import SHA1

from h_mac import hmac
from Crypto.Random import random

from hashlib import sha256 
import math

def sha256_aux(x):

    return sha256(x).digest()
    
def hmac_sha256(key, message):
    """Returns the HMAC-SHA256 for the given key and message. Written
    following Wikipedia pseudo-code."""

    if len(key) > 64:
        key = sha256(key).digest()
    if len(key) < 64:
        key += b'\x00' * (64 - len(key))

        
    if len(key) > 64:
        key = unhexlify(sha1(key))
    if len(key) < 64:
        key += b'\x00' * (64 - len(key))

    o_key_pad = bytes(xor_byte_arrays(b'\x5c' * 64, key))
    i_key_pad = bytes(xor_byte_arrays(b'\x36' * 64, key))

    return sha256_aux(o_key_pad + bytes(sha256_aux(i_key_pad + message)))


def computer_interdmediate(A, B):
    
    msg = str(A).encode('ascii') + str(B).encode('ascii')
    m = sha256()
    m.update(msg)
    return bytes_to_int([i for i in m.digest()])
        

class Server(object):

    '''Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
    '''
    def __init__(self, N, P, g=2, k=3):

        self.N = N
        self.password = string_to_list(P)
        self.g = g
        self.k = k
        self.secret_key = random.randint(0, N)
        
        m = sha256()

        self.salt = random.randint(0, N)

        num_bytes = int(math.log(self.salt, 2))
        mixture = int_to_bytes(self.salt, num_bytes) + self.password

        m.update(bytes(mixture))
        xh = [i for i in m.digest()]        
        x = bytes_to_int(xh)
        
        self.v = pow(self.g, x, self.N)

        # this is not the usual B but it's still DH think of B = v +
        # B' where both of them are public keys generated by two
        # secret keys
        # v by x which comes from password and salt
        # B' which is the regular secret key
        
        self.B = k*self.v + pow(g, self.secret_key, N)


    def receive_rest(self, I, A):
        
        self.email = I
        self.A = A
        self.u = computer_interdmediate(self.A, self.B)

    def compute_shared_secret(self):
        # Generate S = (A * v**u) ** b % N
        # Generate K = SHA256(S)

        S = pow(self.A* pow(self.v, self.u, self.N),
                self.secret_key,
                self.N)

        m = sha256()
        m.update(str(S).encode('ascii'))
        self.shared_secret = m.digest()

        self.hm = hmac_sha256(str(self.shared_secret).encode('ascii'),
                              str(self.salt).encode('ascii'))
    

    def validate(self, recd):

        if recd == self.hm:
            print(GREEN, "OK", RESET)
        else:
            print(RED, "You effed up", RESET)
            
class Client(object):

    def __init__(self, N, P, g=2, k=3):

        self.N = N
        self.password = string_to_list(P)
        self.g = g
        self.k = k
        self.secret_key = random.randint(0, N)

        self.A = pow(self.g, self.secret_key, self.N)
        
    def other_parameters(self, salt, B):

        self.B = B
        self.salt = salt
        self.u = computer_interdmediate(self.A, self.B)        
        
    def compute_shared_secret(self):

        # Generate string xH=SHA256(salt|password)
        # Convert xH to integer x somehow (put 0x on hexdigest)
        m = sha256()        
        num_bytes = int(math.log(self.salt, 2))
        mixture = int_to_bytes(self.salt, num_bytes) + self.password

        m.update(bytes(mixture))
        xh = [i for i in m.digest()]        
        x = bytes_to_int(xh)
        
        # Generate S = (B - k * g**x)**(a + u * x) % N
        temp1 = self.B - self.k* pow(self.g, x, self.N)        
        temp2 = self.secret_key + self.u*x        
        S = pow( temp1, temp2, self.N )
        
        m = sha256()
        m.update(str(S).encode('ascii'))
        self.shared_secret = m.digest()

        self.hm = hmac_sha256(str(self.shared_secret).encode('ascii'),
                              str(self.salt).encode('ascii'))]
        
    
        
if __name__ == '__main__':
# Generated using "openssl dhparam -text 1024".
    # N = int("008c5f8a80af99a7db03599f8dae8fb2f75b52501ef54a827b8a1a586f14dfb20d6b5e2ff878b9ad6bca0bb9"
    #     "18d30431fca1770760aa48be455cf5b949f3b86aa85a2573769e6c598f8d902cc1a0971a92e55b6e04c4d07e"
    #     "01ac1fa9bdefd1f04f95f197b000486c43917568ff58fafbffe12bde0c7e8f019fa1cb2b8e1bcb1f33", 16)
    N = 37
    I = 'leo@messi.com'
    P = 'cristiano'
    
    s  = Server(N, P)    
    c  = Client(N, P)
    
    c.other_parameters(s.salt, s.B)
    s.receive_rest(I, c.A)

    s.compute_shared_secret()
    c.compute_shared_secret()

    s.validate(c.hm)