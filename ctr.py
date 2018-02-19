from utils import *
from cbc import *

import numpy as np
import copy

AES_BLOCK_SIZE = 16

def AES_CTR(pText, key, nonce, encrypt=True):

    '''
    Expect nonce to be 8 bytes
    '''
    num_blocks = math.ceil(len(pText) / AES_BLOCK_SIZE)

    counters = [[i for i in k.to_bytes(8, "little")] for k in range(num_blocks)]

    streams = [nonce + c for c in counters]

    encrypted_streams = [AES_single_block(s, key, encrypt=encrypt) for s in streams]
    
    flat_stream = flatten(encrypted_streams)

    return [pText[i] ^ flat_stream[i] for i in range(len(pText))]


def CTR_keystream(num_blocks, key, nonce):

    counters = [[i for i in k.to_bytes(8, "little")] for k in range(num_blocks)]

    streams = [nonce + c for c in counters]

    encrypted_streams = [AES_single_block(s, key, encrypt=True) for s in streams]
    
    return flatten(encrypted_streams)
