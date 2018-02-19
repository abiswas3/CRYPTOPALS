from random import randint
from binascii import unhexlify, hexlify
from struct import pack, unpack

from Crypto.Hash import MD4

def left_rotate(n, b):
    '''
    Rotate n left by b steps
    '''
    return ((n << b) | (n >> (32 - b))) & 0xffffffff

class MD4:
    """Adapted from: https://github.com/FiloSottile/crypto.py/blob/master/3/md4.py"""
    buf = [0x00] * 64

    _F = lambda self, x, y, z: ((x & y) | (~x & z))
    _G = lambda self, x, y, z: ((x & y) | (x & z) | (y & z))
    _H = lambda self, x, y, z: (x ^ y ^ z)

    def __init__(self,
                 message,
                 ml=None,
                 A=0x67452301,
                 B=0xefcdab89,
                 C=0x98badcfe,
                 D=0x10325476):
        
        self.A, self.B, self.C, self.D = A, B, C, D

        if ml is None:
            ml = len(message) * 8

        length = pack('<Q', ml)

        while len(message) > 64:
            self._handle(message[:64])
            message = message[64:]

        message += b'\x80'
        message += bytes((56 - len(message) % 64) % 64)
        message += length

        while len(message):
            self._handle(message[:64])
            message = message[64:]

    def _handle(self, chunk):
        X = list(unpack('<' + 'I' * 16, chunk))
        A, B, C, D = self.A, self.B, self.C, self.D

        for i in range(16):
            k = i
            if i % 4 == 0:
                A = left_rotate((A + self._F(B, C, D) + X[k]) & 0xffffffff, 3)
            elif i % 4 == 1:
                D = left_rotate((D + self._F(A, B, C) + X[k]) & 0xffffffff, 7)
            elif i % 4 == 2:
                C = left_rotate((C + self._F(D, A, B) + X[k]) & 0xffffffff, 11)
            elif i % 4 == 3:
                B = left_rotate((B + self._F(C, D, A) + X[k]) & 0xffffffff, 19)

        for i in range(16):
            k = (i // 4) + (i % 4) * 4
            if i % 4 == 0:
                A = left_rotate((A + self._G(B, C, D) + X[k] + 0x5a827999) & 0xffffffff, 3)
            elif i % 4 == 1:
                D = left_rotate((D + self._G(A, B, C) + X[k] + 0x5a827999) & 0xffffffff, 5)
            elif i % 4 == 2:
                C = left_rotate((C + self._G(D, A, B) + X[k] + 0x5a827999) & 0xffffffff, 9)
            elif i % 4 == 3:
                B = left_rotate((B + self._G(C, D, A) + X[k] + 0x5a827999) & 0xffffffff, 13)

        order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i in range(16):
            k = order[i]
            if i % 4 == 0:
                A = left_rotate((A + self._H(B, C, D) + X[k] + 0x6ed9eba1) & 0xffffffff, 3)
            elif i % 4 == 1:
                D = left_rotate((D + self._H(A, B, C) + X[k] + 0x6ed9eba1) & 0xffffffff, 9)
            elif i % 4 == 2:
                C = left_rotate((C + self._H(D, A, B) + X[k] + 0x6ed9eba1) & 0xffffffff, 11)
            elif i % 4 == 3:
                B = left_rotate((B + self._H(C, D, A) + X[k] + 0x6ed9eba1) & 0xffffffff, 15)

        self.A = (self.A + A) & 0xffffffff
        self.B = (self.B + B) & 0xffffffff
        self.C = (self.C + C) & 0xffffffff
        self.D = (self.D + D) & 0xffffffff

    def digest(self):
        return pack('<4I', self.A, self.B, self.C, self.D)

    def hex_digest(self):
        return hexlify(self.digest()).decode()

def state_from_md4(digest):
    return unpack('<4I', unhexlify(digest))
    
def md_pad(message):
    """Pads the given message the same way the pre-processing of the MD4 algorithm does.
    Only return extra bit
    """
    ml = len(message) * 8

    message += b'\x80'
    message += bytes((56 - len(message) % 64) % 64)
    message += pack('<Q', ml)
    
    return message


if __name__ == '__main__':
    
    key = b'AACC'

    # This is the same as updating the state with Hello, then updating
    # the state with world
    message = md_pad(key + b'Hello!,') + b' world'
    
    digest = MD4(message).hex_digest()
    print(digest)

    # The above shit is decomposed into the following two steps:
    
    #Now say we didn't know what the message was but we had the
    #digest: we could pull out state
    message = key + b'Hello!,'
    digest = MD4(message).hex_digest()
    
    a,b,c,d = state_from_md4(digest)
    
    # Now we're starting at a point where we've already done the hello
    # bit: by imposing state; the mac_length is editted to pretend it
    # happened naturally and the input wasn't just world
    message = b' world'
    digest = MD4(message,
                  A=a, B=b, C=c, D=d,
                  ml=len(md_pad(key + b'Hello!,') + b' world') * 8).hex_digest()
    print(digest)
    print()

    



    
