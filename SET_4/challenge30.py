import sys
import struct
sys.path.append('../')

from utils import *
from cbc import *

from md4 import MD4, md_pad, state_from_md4

from random import randint

def verify_mac(m, m_auth):
    '''
    m: message for which I should compute mac
    m_auth : the digest i've computed
    '''
    expected = compute_mac(m)

    for i in range(len(expected)):
        if expected[i] != m_auth[i] :
            return False

    return True

def is_admin(m, m_auth):
    '''
    Double check: first check if the mac provided is the right one
    and then look for admin=true
    '''

    if not verify_mac(m, m_auth):
        return False

    return b';admin=true' in m


def compute_mac(token):
    '''
    hides the key
    '''
    return MD4(key+token).hex_digest()

if __name__ == '__main__':

    # don't actually know contents but won't need it.
    token = b"comment1=cooking%20MCs;userdata=foo;" + \
            b"comment2=%20like%20a%20pound%20of%20bacon"

    wanna_insert = b';admin=true'

    # I actually don't know what this is: for the sake of simulation
    # say this is it
    with open("/usr/share/dict/words") as dictionary:
        candidates = dictionary.readlines()

    key = candidates[randint(0, len(candidates) - 1)].rstrip().encode()

    print("They actual key was {} of size {}".format(key, len(key)))

    # THIS IS WHAT I REALLY WANT ACCESS TO: fuck knows what the key is
    digest =  compute_mac(token)

    # Get me state from the real deal: they key step
    A, B, C, D = state_from_md4(digest)

    # Now take guesses at key length : i know it's 16 so let's try till 20 bytes
    # for klen in range(0, 20):
    if 1 == 1:
        klen = len(key)
        # All i need is the keysize to be right, i already have state
        # from that the key generates

        # This is the same as calling sha.digest with the correct shit and then
        # calling sha.digest again with just wanna_insert
        # to get a final state
        # since that shit is padded; it'll roll over
        poisoned_ml = len(b'A'*klen + token + md_pad(b'A'*klen + token) + wanna_insert) * 8

        # What i need knowledge of :
        # * key length
        # * length of token ( i dont even need the contents)
        # * the token i want to insert - trivially should have access to this
        poisoned_mac = MD4(wanna_insert,
                           ml=poisoned_ml,
                           A=A,
                           B=B,
                           C=C,
                           D=D).hex_digest()

        print(poisoned_mac)
        print(BLUE)
        print(compute_mac(token + md_pad(b'A'*klen + token) + wanna_insert))
        print(RESET)
        # Now the poisoned mac i have is actually the digest you get once
        # you start with just key+token and then call digest; followed by a call to wanna inset

        # by token + padding(...) we get the state ready for our
        # poisoned mac to match # Now I've stuck an arbitrary string
        # into the token and still got the digest to match up
        # so still presevering that the token is what it was supposed to be

        # I don't use he real key anywhere
        if is_admin(token + md_pad(b'A'*klen + token) + wanna_insert, poisoned_mac):
            print("The guess key size was :", klen)
