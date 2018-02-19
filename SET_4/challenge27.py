import sys
sys.path.append('../')

from utils import *
from cbc import *
from ctr import *

def escape_them_characters(new_payload):

    '''
    Replacing with a question mark
    '''
    return "".join([i if i !=';' and i != '=' else '?'.format(i) for i in new_payload])



def encrypt(text, key, nonce):
    

    cText = encrypt_general_purpose_CBC(text,
                                        nonce,
                                        AES_single_block,
                                        AES_BLOCK_SIZE,
                                        key)

    return cText

def oracle(cText, key, nonce):

    recoveredText = decrypt_general_purpose_CBC(flatten_list_of_lists(cText),
                                                nonce,
                                                AES_single_block,
                                                AES_BLOCK_SIZE,
                                                key)

    for block in recoveredText:
        for x in block:
            if x > 128:
                return -1, recoveredText
        
    return 1, ('admin=' in list_to_string(recoveredText))

if __name__ == '__main__':

    key = string_to_list('YELLOW SUBMARINE')
    nonce= key

    # look at notebook to see why this really works
    
    pText =  string_to_list('YELLOW SUBMARINE'+
                            'YELLOW SUBMARINE'+
                            'YELLOW SUBMARINE')
    

    # This is what I can see
    cText = encrypt(pText, key, nonce)

    for i in range(16):
        cText[1][i] = 0

    cText[2] = cText[0][:]
    
    flag, text = oracle(cText, key, nonce)

    
    # Regular behaviour
    print("Key: ", list_to_string([text[0][i] ^ text[2][i] for i in range(16)]))    
