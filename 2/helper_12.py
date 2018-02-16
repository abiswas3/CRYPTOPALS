import sys
sys.path.append('../')

from utils import *
from cbc import *

import numpy as np
from sklearn.metrics import accuracy_score

AES_BLOCK_SIZE = 16


def if_array_equal(lst_a, lst_b):

    for i,j in zip(lst_a, lst_b):
        if i != j:
            return False

    return True


def oracle(myText, unknown_pText, unknown_key, block_size):

    temp = myText + unknown_pText
    plain_text_padded = pkcs7(temp, block_size)
    cipher_text = AES_ECB(plain_text_padded, unknown_key, encrypt=True)
    return cipher_text


def make_dict(block_size,
              prefix,
              unknown_ptext,
              unknown_key):

    # each crafted input % block_size == 0
    crafted_inputs = [prefix + [i] for i in range(256)]
    
    dictionary = [oracle(text,
                         unknown_ptext,
                         unknown_key,
                         block_size)
                  for i, text in enumerate(crafted_inputs)]

    
    return dictionary

def check(d, lst, index, block_size):

    # print(index*block_size, index*block_size+block_size)
    for i, row in enumerate(d):
        if if_array_equal(row[index*block_size:index*block_size+block_size], lst[index*block_size:index*block_size+block_size]):
            return i

    return -1
