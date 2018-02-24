import sys
sys.path.append('../')

from utils import *
from cbc import *
from sha1 import SHA1

from h_mac import hmac
from Crypto.Random import random

from hashlib import sha256
import math

'''
Brute force search words- dumb!!!
'''
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

        print(CYAN, "MIX: ", mixture, RESET)
        m.update(bytes(mixture))
        xh = [i for i in m.digest()]
        x = bytes_to_int(xh)
        print(CYAN, "x {}\n".format(x), RESET)

        # Generate S = (B - k * g**x)**(a + u * x) % N
        temp1 = self.B
        temp2 = self.secret_key + self.u*x
        S = pow( temp1, temp2, self.N )

        m = sha256()
        m.update(str(S).encode('ascii'))
        self.shared_secret = m.digest()

        self.hm = hmac_sha256(str(self.shared_secret).encode('ascii'),
                              str(self.salt).encode('ascii'))


        print(CYAN, "hm", self.hm, RESET)

def sha256_aux(x):

    m = sha256()
    m.update(x)
    return m.digest()


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


class FakeServer(object):

    '''Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
    '''
    def __init__(self, N, g=2, k=3):

        self.N = N
        self.g = g
        self.k = k
        self.secret_key = random.randint(0, N)

        self.salt = 25

        # Regular Diffie Hellman
        self.B = pow(g, self.secret_key, N)

    def generate_v(self, password):

        num_bytes = int(math.log(self.salt, 2))
        mixture = int_to_bytes(self.salt, num_bytes) + password
        # print(GREEN, "MIX: ", mixture, RESET)

        m = sha256()
        m.update(bytes(mixture))
        xh = [i for i in m.digest()]
        x = bytes_to_int(xh)

        # print(GREEN, "x {1}\n Password: {0} \n".format(list_to_string(password), x), RESET)

        return pow(self.g, x, self.N)

    def receive_rest(self, I, A):

        self.email = I
        self.A = A
        self.u = computer_interdmediate(self.A, self.B)


    def find_password(self, hm):

        with open("/usr/share/dict/words") as dictionary:
            candidates = [i.strip() for i in dictionary.readlines()]


        for candidate in candidates:

            print(candidate)
            # Strip the word

            candidate = string_to_list(candidate)
            v = self.generate_v(candidate)

            self.compute_shared_secret(v)

            if self.hm == hm:
                print(GREEN, list_to_string(candidate), RESET)
                break

    def compute_shared_secret(self, v):

        S = pow(self.A* pow(v, self.u, self.N),
                self.secret_key,
                self.N)

        m = sha256()
        m.update(str(S).encode('ascii'))
        self.shared_secret = m.digest()

        self.hm = hmac_sha256(str(self.shared_secret).encode('ascii'),
                              str(self.salt).encode('ascii'))



if __name__ == '__main__':
    # Generated using "openssl dhparam -text 1024".
    N =0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

    I = 'leo@messi.com'
    P = 'algorithm'

    fs  = FakeServer(N) # fake server does not have password


    c  = Client(N, P)

    c.other_parameters(fs.salt, fs.B)
    fs.receive_rest(I, c.A)
    c.compute_shared_secret()
    fs.find_password(c.hm)
