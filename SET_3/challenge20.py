import sys
sys.path.append('../')

from utils import *
from cbc import *
from ctr import *
from solvers import decode_single_xor_cipher

if __name__ == '__main__':

    print('CHALLENGE 20')
    with open('20_data.txt') as f:
        a = f.readlines()

    a = [i.strip() for i in a]

    # list of list of bytes
    pTexts = [byteString_to_list(base64.b64decode(''.join(i))) for i in a]

    key = generate_AES_key()
    nonce = [0]*8 # this should be random

    cTexts = [AES_CTR(i, key, nonce, encrypt=True) for i in pTexts]

    smallest_cText = min([len(i) for i in cTexts])

    keys = []
    for index in range(smallest_cText):
        cipher_text = [c[index] for c in cTexts]
        keys.append(decode_single_xor_cipher(cipher_text, debug=False)["key"])


    answers = []
    for c in cTexts:
        answers.append(list_to_string(xor_byte_arrays(keys, c[:smallest_cText])))

    print(answers)


    
    
