import sys
sys.path.append('../')

from utils import *
from cbc import *

import numpy as np
import copy

def decrypt_and_verify_helper(cText, nonce, key):

    decryptedText =  decrypt_general_purpose_CBC(flatten_list_of_lists(cText),
                                                 nonce,
                                                 AES_single_block,
                                                 AES_BLOCK_SIZE,
                                                 key)


    return verify_pkcs7(flatten_list_of_lists(decryptedText))

def make_attack_input(index,
                      guess,
                      prev):

    new_cipher = []
    for i in range(index):
        pos = -(i+1)
        new_cipher.append(prev[pos] ^ guess[pos] ^ index)


    return new_cipher[::-1]


def decrypt_and_verify(ans, choice, index, cText, nonce, key, cTextIndex):

    '''
    ans: answer so far
    choice : choice for guess
    '''

    guess = [0]* (AES_BLOCK_SIZE - len(ans)) + ans[::-1]
    guess[-(index)] = choice


    attack = make_attack_input(index,
                               guess,
                               cText[cTextIndex])

    c_Text_copy = copy.deepcopy(cText)
    c_Text_copy[cTextIndex][-(index):] = attack

    x = decrypt_and_verify_helper(c_Text_copy, nonce, key)

    return x


############################## SETUP ##########################################
AES_BLOCK_SIZE = 16

# Select 1 out 10 given random strings
choices = ['MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
           'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
           'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
           'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
           'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
           'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
           'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
           'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
           'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
           'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']

index = np.random.choice(len(choices))
pText = [i for i in base64.b64decode(''.join(choices[index]))]

# # Generate Random AES key
key = generate_AES_key()
# some random 16 byte number
nonce = [i for i in generate_AES_key()]

cText = encrypt_general_purpose_CBC(pText,
                                    nonce,
                                    AES_single_block,
                                    AES_BLOCK_SIZE,
                                    key)

cText.insert(0, nonce)
print(RED, "ORIGINAL")
print(list_to_string(pText))
print(RESET, '\n')

################### ATTACK LAND ####################################
SOLN = []
for block in range(len(cText)-1):    
    cTextIndex = -2
    ans = []
    for index in range(1, AES_BLOCK_SIZE+1):
        for choice in range(2, 256):
            attack_ind = choice
            x = decrypt_and_verify(ans,
                                   attack_ind,
                                   index,
                                   cText[:len(cText) - block],
                                   nonce,
                                   key,
                                   cTextIndex)
            if x == True:
                ans.append(attack_ind)
                break

    SOLN.append(list_to_string(ans[::-1]))
    
print(GREEN, 'SOLUTION')
print(''.join(flatten_list_of_lists(SOLN[::-1])))
print(RESET)

