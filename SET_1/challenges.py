import sys
sys.path.append('../')
from utils import *
from frequency_analysis import *
from solvers import *

import numpy as np
from Crypto.Cipher import AES
from Crypto import Random

def challenges(num):

    d = {1: challenge1,
         2: challenge2,
         3: challenge3,
         4: challenge4,
         5: challenge5,
         6: challenge6,
         7: challenge7,
         8: challenge8
    }

    return d[num]()

    
def challenge1():

    '''
    Convert hex to base64
    '''

    print('CHALLENGE 1')
    
    with open('../DATA/challenge1_input.txt') as f:
        a = f.readline().strip()


    temp = hex_to_list(a)
    ans  = list_to_base64(temp)

    #==============================================
    # CHECK IF OUTPUT MATCHES
    #==============================================
    with open('data/challenge1_output.txt') as f:
        a = f.readline().strip()

    print('Did the output match ?')
    print(ans == a)


def challenge2():

    '''
    Take 2 equal sized hex strings and xor them
    '''

    print('CHALLENGE 2')    
    with open('../DATA/challenge2_inputa.txt') as f:
        a = f.readline().strip()

    with open('../DATA/challenge2_inputb.txt') as f:
        b = f.readline().strip()
    
    x = hex_to_list(a)
    y = hex_to_list(b)

    z = xor_byte_arrays(x,y)
    ans = list_to_hex(z)

    #==============================================
    # CHECK IF OUTPUT MATCHES
    #==============================================
    with open('data/challenge2_output.txt') as f:
        o = f.readline().strip()

    print('Did the output match ?')
    print(ans == o)


def challenge3():

    '''Single-byte XOR cipher The hex encoded string:
    1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
    has been XOR'd against a single character. Find the key, decrypt the message.
    
    You can do this by hand. But don't: write code to do it for you.    
    How? Devise some method for "scoring" a piece of English
    plaintext. Character frequency is a good metric. Evaluate each
    output and choose the one with the best score.

    '''
    print('CHALLENGE 3')
    with open('../DATA/challenge3_input.txt') as f:
        cipher_text = f.readline().strip()

    cipher_text = hex_to_list(cipher_text)
    
    range_of_keys = range(256)
    # range_of_keys = [91]
    solutions = []
    
    for key in range_of_keys:
        buffer = [key for i in cipher_text]
        candidate_solution = xor_byte_arrays(cipher_text, buffer)        
        solutions.append(get_score(candidate_solution))
        
    xor_key = np.argmin(solutions)
    print('XOR KEY: ', xor_key)
    solution = list_to_string(xor_byte_arrays(cipher_text, [xor_key for i in cipher_text]))

    print(solution)


def challenge4():

    print('CHALLENGE 4')    
    with open('../DATA/challenge4_input.txt') as f:
        a = f.readlines()

    # clean up
    a = [x.strip() for x in a]

    solutions = []
    score = []
    
    for cipher_text in a:
        cipher_text = hex_to_list(cipher_text)
        candidate_solution = decode_single_xor_cipher(cipher_text, debug=False)['solution']
        
        score.append(get_score(candidate_solution))
        solutions.append(candidate_solution)

    index = np.argmin(score)
    solution = list_to_string(solutions[index])
    print(solution)


def challenge5():
    print('CHALLENGE 5')    
    with open('../DATA/challenge5_input.txt') as f:
        plain_text = f.readlines()

    plain_text = [i.strip() for i in plain_text]    
    plain_text = '\n'.join(plain_text)
    plain_text = string_to_list(plain_text)
    
    key = 'ICE'
    key = [ord(i) for i in key]

    cipher_text = block_xor_encrypt(plain_text, key)

    ans = list_to_hex(cipher_text)

    #==============================================
    # CHECK IF OUTPUT MATCHES
    #==============================================
    with open('data/challenge5_output.txt') as f:
        a = f.readline().strip()

    print('Did the output match ?')

    for i,j in zip(ans,a):
        if i!=j:
            print('NO')
            return

    print('YES')


def challenge6():
    '''There's a file here. It's been base64'd after being encrypted with repeating-key XOR.
    
    Decrypt it.

    Hint: key sizes in the range of 2-40
    '''
    print('CHALLENGE 6')
    with open('../DATA/challenge6_input.txt') as f:
        a = f.readlines()

    #==============FIND CORRECT KEY SIZE====================        
    byte_arr = base64_to_list(''.join(a))
    hamming_scores = []
    for key_size in range(2,40):
        
        byte_mat = make_blocks(byte_arr, key_size)
        score = hamming_distance_rows(byte_mat)
        hamming_scores.append(score)
        
    indices = np.argsort(hamming_scores)
    # willing to take a look at the best threshold number of keysizes
    # Since i used averaging of 4 and not 2, i got away with minimum guy only
    # and didn't have to test out many guys
    threshold = 1
    
    keysizes = np.arange(40)[indices[:threshold]] + 2
    optimal_key_size = keysizes[0]
    #=======================================================        


    
    #========DECRYPT THE PRIVATE KEY==========================            
    byte_mat = make_blocks(byte_arr, optimal_key_size)    
    byte_mat_T = transpose(byte_mat)
    
    # Have key size but not key values, that's not hard
    # each column of byte array is a single byte xor
    # we can brute force it and use freq analysis to help us out
    private_key = []
    for i, col in enumerate(byte_mat_T):
        temp = decode_single_xor_cipher(list(col), debug=False)
        private_key.append(temp['key'])

    key = private_key
    #=======================================================

    
    print('PRIVATE KEY= {} \n'.format(list_to_string(private_key)))
    #============HAVE PRIVATE KEY===========================
    ans = list_to_string(block_xor_encrypt(byte_arr, key))
    print(ans)    
    #=======================================================        


def challenge7():

    print('CHALLENGE 7')
    with open('../DATA/challenge7_input.txt') as f:
        a = f.readlines()
        a = [i.strip() for i in a]
        
    c = base64.b64decode(''.join(a)) # base64 string    
    k= b'YELLOW SUBMARINE'
    
    cipher = AES.new(k, AES.MODE_ECB)
    p = cipher.decrypt(c)

    print(list_to_string(p))

    return p

def challenge8():

    '''
    This is very contrived: re- did in this challenge 2 using 
    hamming distance
    '''

    print('CHALLENGE 8')
    with open('../DATA/challenge8_input.txt') as f:
        a = f.readlines()

    a = [hex_to_list(i.strip()) for i in a]
    
    count_arr = []
    for cipher in a:

        if len(cipher) % 16 != 0:
            # Maximum value for that cipher so he never gets selected
            count_arr.append(len(cipher)//16)
            continue
        
        # this the block matrix
        block_matrix = []
        # we hope that when using ECB mode
        # the same plain text will get mapped to the same
        # cipher text.
        # Thus there will be a bunch of repeats across the cipher text
        # if the
        # plain texts were the same
              
        for j in range(len(cipher)//16):    
            start = j*16
            end = (j+1)*16

            block = list_to_hex(cipher[start:end])
            block_matrix.append(block)

        # how many blocks mapped to the same shit
        count_arr.append(len(np.unique(block_matrix)))

    print(np.argmin(count_arr), "i'th row in file")
            
    
if __name__ == '__main__':

    experiments = [1, 2, 3, 4, 5, 6, 7, 8]
    # experiments = [6]
    for i in experiments:
        challenges(i)
        print()
