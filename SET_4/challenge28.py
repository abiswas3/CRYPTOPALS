import sys
sys.path.append('../')

from utils import *
import struct
from struct import pack, unpack
from sha1 import SHA1, md_pad, state_from_sha1

if __name__ == '__main__':
    
    key = b'AACC'

    # This is the same as updating the state with Hello, then updating
    # the state with world
    message = md_pad(key + b'Hello!,') + b' world'
    digest = SHA1(message, debug=False)
    print(digest)

    # The above shit is decomposed into the following two steps:
    
    #Now say we didn't know what the message was but we had the
    #digest: we could pull out state
    message = key + b'Hello!,'
    digest = SHA1(message, debug=False)
    h0, h1, h2, h3, h4 = state_from_sha1(digest)
    
    # Now we're starting at a point where we've already done the hello
    # bit: by imposing state; the mac_length is editted to pretend it
    # happened naturally and the input wasn't just world
    message = b' world'
    digest = SHA1(message,
                  h0=h0,
                  h1=h1,
                  h2=h2,
                  h3=h3,
                  h4=h4,
                  mac_length=len(md_pad(key + b'Hello!,') + b' world') * 8)
    print(digest)
    print()

    



