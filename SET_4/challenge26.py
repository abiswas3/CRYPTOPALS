import sys
sys.path.append('../')

from utils import *
from cbc import *
from ctr import *

import numpy as np

def escape_them_characters(new_payload):

    '''
    Replacing with a question mark
    '''
    return "".join([i if i !=';' and i != '=' else '?'.format(i) for i in new_payload])


def encrypt(text, key, nonce):
    
    # all = and ; are replaced with ?
    modified_pText = escape_them_characters(list_to_string(text))

    cText =  AES_CTR(string_to_list(modified_pText),
                     key,
                     nonce,
                     encrypt=True)

    return cText

def oracle(cText, key, nonce):

    recoveredText = AES_CTR(cText, key, nonce, encrypt=True)
    
    return ('admin=' in list_to_string(recoveredText))
    

if __name__ == '__main__':
    
    key = string_to_list('YELLOW SUBMARINE')
    nonce= [np.random.randint(0, high=256)]*8

    prefix = string_to_list("comment1=cooking%20MCs;userdata=")
    payload = string_to_list("admin=true")
    suffix = string_to_list(";comment2=%20like%20a%20pound%20of%20bacon")
    
    pText =  prefix + payload + suffix
    
    print('admin=' in list_to_string(pText))

    # This is what I can see
    cText = encrypt(pText, key, nonce)
    
    # Regular behaviour
    print(oracle(cText, key, nonce))

    # I need to fuck with the cText so I gain access
    
    # The key stream doesn't give a bollox about the Ctext it only
    # depends on key and noce and position So regardless the same
    # keystream is produced for whatever the fuck i replace my Ctext
    # with
    offset = len(prefix) + len('admin')
    for ch in range(256):
        cText[offset] = ch
        if oracle(cText, key, nonce):
            print('We are done: replace index {} of C-text with {}'.format(offset, ch))
            break
        
    # Sanity check]
    cText[offset] = ch
    print(list_to_string(AES_CTR(cText, key, nonce, encrypt=True)))
