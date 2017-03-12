from utils import *
import numpy as np
from frequency_analysis import *


def decode_single_xor_cipher(cipher_text, debug=False):
    '''Single-byte XOR cipher The hex encoded string:
    1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
    has been XOR'd against a single character. Find the key, decrypt the message.
    
    You can do this by hand. But don't: write code to do it for you.    
    How? Devise some method for "scoring" a piece of English
    plaintext. Character frequency is a good metric. Evaluate each
    output and choose the one with the best score.

    '''
    
    range_of_keys = range(256)
    solutions = []    
    for key in range_of_keys:
        buffer = [key for i in cipher_text]
        candidate_solution = xor_byte_arrays(cipher_text, buffer)        
        solutions.append(get_score(candidate_solution))

        
    xor_key  = np.argmin(solutions)
    
    if debug:
        # print off top 5 keys
        inds = np.argsort(solutions)[:7]
        print([chr(i) for i in  inds] )
    
    solution = xor_byte_arrays(cipher_text, [xor_key for i in cipher_text])

    return {'solution': solution, 'key':xor_key}


def block_xor_encrypt(plain_text_arr, key):

    ''' Implement repeating-key XOR Here is the opening stanza of an
   important work of the English language:

   Burning 'em, if you ain't quick and nimble I go crazy when I hear a
   cymbal Encrypt it, under the key "ICE", using repeating-key XOR.

   In repeating-key XOR, you'll sequentially apply each byte of the
   key; the first byte of plaintext will be XOR'd against I, the next
   C, the next E, then I again for the 4th byte, and so on.

   It should come out to:
   0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
   a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

   Encrypt a bunch of stuff using your repeating-key XOR
   function. Encrypt your mail. Encrypt your password file. Your .sig
   file. Get a feel for it. I promise, we aren't wasting your time
   with this.

    '''


    buffer = []
    index = 0

    for i in range(len(plain_text_arr)):        
        buffer.append(key[index])
        index = (index + 1) % len(key)

    return xor_byte_arrays(plain_text_arr, buffer)


