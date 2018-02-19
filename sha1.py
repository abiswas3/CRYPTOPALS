
from utils import *
import struct

def SHA1(message,         
         h0 = 0x67452301,
         h1 = 0xefcdab89,
         h2 = 0x98badcfe,
         h3 = 0x10325476,
         h4 = 0xc3d2e1f0,
         mac_length=None, debug=False):
    
    return _SHA1(message, h0, h1, h2, h3, h4, mac_length, debug)

def _SHA1(message, h0, h1, h2, h3, h4, ml, debug):
    
    '''
    message will be list of bytes based on my API
    '''

    bytes = ""
        
    # Pre-processing: append the bit '1' to the message e.g. by
    # adding 0x80 if message length is a multiple of 8 bits.
    # append 0 ≤ k < 512 bits '0', such that the resulting message
    # length in bits is congruent to −64 ≡ 448 (mod 512) append
    # ml, the original message length, as a 64-bit big-endian
    # integer. Thus, the total length is a multiple of 512 bits.
    
    for n in range(len(message)):
        bytes+='{0:08b}'.format(message[n])


    bits = bytes+"1"
    pBits = bits[:]

    #pad until length equals 448 mod 512
    while len(pBits)%512 != 448:
        pBits+="0"

    # append the original length
    # The -1 is for the 1 we added earlier
    if ml == None:
        pBits+='{0:064b}'.format(len(bits)-1)
    else:
        pBits+='{0:064b}'.format(ml)

    def chunks(l, n):
        '''
        l : list i want to chunk up
        n : chunk interval size
        '''
        return [l[i:i+n] for i in range(0, len(l), n)]

    def rol(n, b):
        '''
        Rotate n left by b steps
        '''
        return ((n << b) | (n >> (32 - b))) & 0xffffffff
    
    # Process the message in successive 512-bit chunks:
    # remember i'm working at the bit level
    counter = 0
    for c in chunks(pBits, 512):

        if debug:
            print(GREEN, counter, RESET)
        counter +=1
        
        # break chunk into sixteen 32-bit big-endian words
        words = chunks(c, 32)

        # Extend the sixteen 32-bit words into eighty 32-bit words:
        w = [0]*80

        # copy over the initial 16 as ints
        for n in range(0, 16):
            w[n] = int(words[n], 2)
            
        for i in range(16, 80):
            w[i] = rol((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1)  

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
         
        #Main loop
        for i in range(0, 80):
            if 0 <= i <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d) 
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = rol(a, 5) + f + e + k + w[i] & 0xffffffff
            e = d
            d = c
            c = rol(b, 30)
            b = a
            a = temp

        h0 = h0 + a & 0xffffffff
        h1 = h1 + b & 0xffffffff
        h2 = h2 + c & 0xffffffff
        h3 = h3 + d & 0xffffffff
        h4 = h4 + e & 0xffffffff

    return hex_to_list('%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4))
        

def state_from_sha1(digest):

    return list_to_hex(digest[:4]), list_to_hex(digest[4:8]), list_to_hex(digest[8:12]), list_to_hex(digest[12:16]), list_to_hex(digest[16:])


def md_pad(m):
    """Pads the given message the same way the pre-processing of the SHA1
    algorithm does. 

    Returns just the padding part not the original message
    """
    ml = len(m) * 8

    m += b'\x80'    
    while (len(m) *8 % 512) != 448:
        m += b'\x00'

    m += struct.pack('>Q', ml)
    
    return m


if __name__ == '__main__':

    key = b'AACC'

    # This is the same as updating the state with Hello, then updating
    # the state with world
    message = key + b'Hello!,' + md_padd(key + b'Hello!,') + b' world'
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
                  h0=int(h0,16),
                  h1=int(h1,16),
                  h2=int(h2,16),
                  h3=int(h3,16),
                  h4=int(h4,16),
                  mac_length=len(key + b'Hello!,'+md_padd(key + b'Hello!,') + b' world') * 8)
    print(digest)
    print()

    



