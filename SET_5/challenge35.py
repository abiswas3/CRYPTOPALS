'''Just simulating; not actually writing a server
'''
import sys
sys.path.append('../')

from utils import *
from cbc import *
from sha1 import SHA1

from h_mac import hmac
from Crypto.Random import random

class Person(object):

    def __init__(self, p, g):

        self.p = p
        self.g = g
        self.secret_key = random.randint(0, p)    
        self.public_key = pow(g, self.secret_key, p)
        self.shared_secret = None

    def generate_shared_secret(self, other):

        self.shared_secret = pow(other,
                                 self.secret_key,
                                 self.p)

    def encrypt_message(self, msg, iv, key):


        to_send = encrypt_general_purpose_CBC(string_to_list(msg),
                                              iv,
                                              AES_single_block,
                                              AES_BLOCK_SIZE,
                                              key)


        return flatten(to_send) + iv


def break_cipher(msg, shared_secret):

    iv = msg[-16:]

    encrypted_message = msg[:-16]

    # secret is 0 cos Eve is a fucker
    key = SHA1(str(shared_secret).encode('ascii'), debug=False)[:16]

    ans = decrypt_general_purpose_CBC(encrypted_message,
                                      iv,
                                      AES_single_block,
                                      AES_BLOCK_SIZE,
                                      key)


    return list_to_string(flatten(ans))


if __name__ == '__main__':

    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

    #################################################################
    # When g = 1: nothing matters s will always be 1
    # No man in the middle needed    
    g = 1
    alice = Person(p, g)
    bob = Person(p,g)

    bob.generate_shared_secret(alice.public_key)
    alice.generate_shared_secret(bob.public_key)
    
    
    # random 16 byte number
    iv = generate_AES_key()
    key = SHA1(str(alice.shared_secret).encode('ascii'), debug=False)[:16]
    pText = 'Leightbon baines plays for Everton'
    cipher = alice.encrypt_message(pText,
                                   iv,
                                   key)
    
    recoveredText = break_cipher(cipher, 1)

    print("Original:  ", pText)
    print("Recovered: ", recoveredText)    
    print()
    
    ##################################################################
    
    # when g = p; attack becomes equivalent to what we did in 34
    # shared secret will be 0 always
    g = p
    alice = Person(p, g)
    bob = Person(p,g)

    bob.generate_shared_secret(alice.public_key)
    alice.generate_shared_secret(bob.public_key)
    
    
    # random 16 byte number
    iv = generate_AES_key()
    key = SHA1(str(alice.shared_secret).encode('ascii'), debug=False)[:16]
    pText = 'Leightbon baines plays for Everton'
    cipher = alice.encrypt_message(pText,
                                   iv,
                                   key)

    # Eve can only see cipher but she knows the shared_secret is 0
    recoveredText = break_cipher(cipher, 0)

    print("Original:  ", pText)
    print("Recovered: ", recoveredText)    
    print()
    
    ####################################################################

    # Look at notebook for analysis
    g = p-1

    alice = Person(p, g)
    bob = Person(p,g)

    bob.generate_shared_secret(alice.public_key)
    alice.generate_shared_secret(bob.public_key)
    
    
    # random 16 byte number
    iv = generate_AES_key()
    key = SHA1(str(alice.shared_secret).encode('ascii'), debug=False)[:16]
    pText = 'Leightbon baines plays for Everton'
    cipher = alice.encrypt_message(pText,
                                   iv,
                                   key)

    
    alice_even = False
    if alice.public_key == 1:
        # alice secret key is even
        alice_even = True

    bob_even = False
    if bob.public_key == 1:
        # alice secret key is even
        bob_even = True


    # if both even thenor even one of them s = 1
    if alice_even or bob_even:
        recoveredText = break_cipher(cipher, 1)

    else:
        recoveredText = break_cipher(cipher, g)

    print("Original:  ", pText)
    print("Recovered: ", recoveredText)    
        
