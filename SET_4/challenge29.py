import sys
import struct
sys.path.append('../')

from utils import *
from cbc import *

from sha1 import SHA1, md_pad, state_from_sha1

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
    return SHA1(key+token)

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
    h0, h1, h2, h3, h4 = state_from_sha1(digest)

    # Now take guesses at key length : i know it's 16 so let's try till 20 bytes
    for klen in range(0, 20):
        # All i need is the keysize to be right, i already have state
        # from that the key generates

        # This is the same as calling sha.digest with the correct shit and then
        # calling sha.digest again with just wanna_insert
        # to get a final state
        # since that shit is padded; it'll roll over
        poisoned_ml = len(md_pad(b'A'*klen + token) + wanna_insert) * 8

        # What i need knowledge of :
        # * key length
        # * length of token ( i dont even need the contents)
        # * the token i want to insert - trivially should have access to this
        poisoned_mac = SHA1(wanna_insert,
                            mac_length=poisoned_ml,
                            h0=int(h0,16),
                            h1=int(h1,16),
                            h2=int(h2,16),
                            h3=int(h3,16),
                            h4=int(h4,16))


        # Now the poisoned mac i have is actually the digest you get once
        # you start with just key+token and then call digest; followed by a call to wanna inset

        # by token + padding(...) we get the state ready for our
        # poisoned mac to match # Now I've stuck an arbitrary string
        # into the token and still got the digest to match up
        # so still presevering that the token is what it was supposed to be

        # I don't use he real key anywhere
        message = token + md_pad(b'A'*klen + token)[len(b'A'*klen + token):] + wanna_insert
        if is_admin(message,
                    poisoned_mac):
            
            print("The guess key size was :", klen)
            
