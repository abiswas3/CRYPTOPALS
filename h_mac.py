import sys
import struct

from md4 import MD4
from sha1 import SHA1

from utils import *

def md4_function(message):

    return MD4(message).hex_digest()

def hmac(key,
         message,
         hash_func,
         block_size=64,
         output_size=20):
    '''
    Defaults selected for SHA-1
    
    @Params:
    key:        Bytes     array of bytes
    message:    Bytes     array of bytes to be hashed
    hash:       String    the hash function to use (e.g. SHA-1)
    blockSize:  Integer   the block size of the underlying hash function (e.g. 64 bytes for SHA-1)
    outputSize: Integer   the output size of the underlying hash function (e.g. 20 bytes for SHA-1)
    
    '''

    if hash_func == 'SHA1':
        h = SHA1
    elif hash_func == 'MD4':
        h = md4_function
        
    if len(key) > 64:
        key = unhexlify(sha1(key))
    if len(key) < 64:
        key += b'\x00' * (64 - len(key))

    o_key_pad = bytes(xor_byte_arrays(b'\x5c' * 64, key))
    i_key_pad = bytes(xor_byte_arrays(b'\x36' * 64, key))


    return h(o_key_pad + bytes(h(i_key_pad + message)))

def sign_request():
    from hashlib import sha1
    import hmac
    
    hashed = hmac.new(key, raw, sha1)    
    # The signature
    return hashed.digest()

if __name__ == '__main__':

    # Verify with a standard hmac library
    key = b"CONSUMER_SECRET&TOKEN_SECRET"
    
    # The Base String as specified here:
    raw = b"BASE_STRING" # as specified by oauth
    
    print([i for i in sign_request()])
    print()
    print(hmac(key, raw, "SHA1"))
