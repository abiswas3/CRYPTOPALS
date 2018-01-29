import sys
sys.path.append('../')

from utils import *
from cbc import *

import numpy as np
from sklearn.metrics import accuracy_score

from helper_12 import *

AES_BLOCK_SIZE = 16

def challenge9():

    '''
    Implement PKCS7 padding
    '''
    lst_of_bytes = string_to_list("YELLOW SUBMARINE")
    block_size = 20
    x = pkcs7(lst_of_bytes, block_size)
    print(x)

def challenge10():

    print('CHALLENGE 10')
    with open('10.txt') as f:
        a = f.readlines()

    a = [i.strip() for i in a]
    # list of bytes
    c = base64.b64decode(''.join(a)) # byte string
    nonce = [0 for i in range(14)] + [ord('&'), ord('c')]
    
    ans = decrypt_general_purpose_CBC(c,
                                      nonce,
                                      AES_single_block,
                                      AES_BLOCK_SIZE,
                                      string_to_list("YELLOW SUBMARINE"))
    # test it out
    for i in ans:
        print(list_to_string(i))


def flip_coin_encrypt_AES(text, key, p=0.5):


    pre, post = np.random.randint(5,
                            high=10,
                            size=2)

    pre_bytes = np.random.randint(0,
                                  high=255, size=pre).tolist()

    post_bytes = np.random.randint(0,
                                   high=255, size=post).tolist()

    new_text = pre_bytes + text + post_bytes

    #Generate a random AES key; that's just 16 random bytes.
    nonce = np.random.randint(0,
                              size=AES_BLOCK_SIZE,
                              high=255).tolist()


    lab = 0
    # Write a function that encrypts data
    if np.random.random() < p:
        # flatten it out for ECB
        new_text = pkcs7(new_text, AES_BLOCK_SIZE)

        c = AES_ECB(new_text, key, encrypt=True)
        # p = [i for i in AES_ECB(c, key, encrypt=False)]
        # print(new_text)
        # print()
        # print(p)
        lab = +1

    else:
        c = encrypt_general_purpose_CBC(new_text,
                                        nonce,
                                        AES_single_block,
                                        AES_BLOCK_SIZE,
                                        key)
        lab = -1

        # Sanity check
        cipherT = [j for i in c for j in i]
        # p = decrypt_general_purpose_CBC(cipherT,
        #                                 nonce,
        #                                 AES_single_block,
        #                                 AES_BLOCK_SIZE,
        #                                 key)
        # print(new_text)
        # print()
        # print([j for i in p for j in i])


    return c, lab


def challenge11():

    print('NOTE i have full control over the input here')
    n = 4
    text = [ord('M') for i in range(n*16)]
    key = np.random.randint(0,
                            size=AES_BLOCK_SIZE,
                            high=255).tolist()
    y = []
    y_hat = []
    for i in range(20):

        x,lab = flip_coin_encrypt_AES(text, key, p=0.5)
        y.append(lab)

        # do something dumb check if num uniqye less than half or not
        x_hat = -1 if len(np.unique(x)) > len(text)//2 else +1
        y_hat.append(x_hat)

    print('Pecentage of labels I got right : ', accuracy_score(y, y_hat)*100, '%')


def challenge12():

    '''Why does this work in ECB? 

    Cos one there's no nonce. But say we even knew the nonce:

    The second block doesn't depend on the first block. So we can pad
    the first block with whatever our heart desires and generate 

    '''
    
    # for now let's assume I know the block size and that it's using
    # ECB : both are trivial to find out if i can control input
    block_size = AES_BLOCK_SIZE

    ############################################
    # I don't have actual access to any of these two I'm just using
    # some random stuff for simulation no where do i actually use
    # knowledge of the key but to calls to the oracle (which needs the
    # key cos this is simulation
    
    key = np.random.randint(0,
                            size=AES_BLOCK_SIZE,
                            high=255).tolist()


    plain_text = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

    plain_text = [i for i in base64.b64decode(plain_text)]
    #-----------------------------------------------

    
    known_string = []

    while True:

        # this is the number of 0's i need to padd to go one short of block_size
        num_same = block_size - len(known_string) % block_size - 1
        prefix = num_same*[0]

        # this is a list of possible answers
        d = make_dict(block_size,
                      prefix + known_string,
                      plain_text, 
                      key)

        # this is the actual encrypted text when the last slot in the buffer
        # is filled with an actual plain text key
        # this attack string has to match some guy in d
        attack_string = [k for k in oracle(prefix,
                                           plain_text,
                                           key,
                                           block_size)]

        
        index = check(d,
                      attack_string,
                      (i//block_size),
                      block_size)
    
        if index == -1:
            break

        known_string += [index]
        
    print(''.join([chr(i) for i in known_string]))


def challenge13():

    block_size=16
    key = generate_AES_key(block_size=block_size)
    
    # now i need replace the role from user to admin
    # i have access to cipher text and i have access to profile for function
    # and the cipher text
    special_email = '0'*10 + 'admin' + 11*'11'
    adversarial_input = string_to_list(JSON_to_cookie(profile_for(special_email)))

    # this maps admin'11'*'11 -> to a cipher text
    admin_cipher = AES_ECB(adversarial_input,
                           key,
                           encrypt=True,
                           block_size=AES_BLOCK_SIZE)[1*block_size:1*block_size+ block_size]
    

    # craft the email so that role= is the end of the block
    # the user is a new block which will be replaced with admin
    final_attack = string_to_list(JSON_to_cookie(profile_for('0'*13)))
    
    cipher = AES_ECB(final_attack,
                     key,
                     encrypt=True,
                     block_size=AES_BLOCK_SIZE)

    # I know cipher is a full block so the block is just padding
    # by pkcs7 rules

    new_cipher = cipher[:-16] + admin_cipher
    
    decrypted_cookie = AES_ECB(new_cipher,
                               key,
                               encrypt=False,
                               block_size=AES_BLOCK_SIZE)
    
    print(list_to_string(decrypted_cookie[:-16+5]))

def challenge14():


    '''
    This is the same thing as 12 but now we have to detect a random offset
    Do this last
    '''
    pass

def challenge15():

    choices = ["ICE ICE BABY\x04\x04\x04\x04",
               "ICE ICE BABY\x05\x05\x05\x05",
               "ICE ICE BABY\x01\x02\x03\x04"               
    ]

    print([verify_pkcs7(string_to_list(padded_text)) for padded_text in choices])

def challenge16():

    '''
    CBC bit flipping attack
    '''

    # The real stuff
    key = string_to_list('YELLOW SUBMARINE')
    block_size = AES_BLOCK_SIZE

    prefix = string_to_list("comment1=cooking%20MCs;userdata=")
    payload = string_to_list("admin=true")
    suffix = string_to_list(";comment2=%20like%20a%20pound%20of%20bacon")

    plain_text =  prefix + payload + suffix    
    nonce = key # no reason just too lazy to create a random one

    
    new_payload = string_to_list(escape_them_characters(list_to_string(payload)))
    new_prefix = prefix[:]
    new_suffix = suffix[:]
    
    plain_text =  new_prefix + new_payload + new_suffix    
    c = encrypt_general_purpose_CBC(plain_text,
                                    nonce,
                                    AES_single_block,
                                    AES_BLOCK_SIZE,
                                    key)
    
    
    ans = decrypt_general_purpose_CBC(flatten_list_of_lists(c),
                                      nonce,
                                      AES_single_block,
                                      AES_BLOCK_SIZE,
                                      key)


    decoded = [list_to_string(i) for i in ans]
    decoded = "".join(flatten_list_of_lists(decoded))
    print('admin= as present?')
    print('admin=' in decoded)
    print()
    
    #############################################################################

    # the only thing i know is that the second block is where admin? shows up
    # infact admin? is the start of the second block- so the 5 byte of the second
    # block is all i care about

    # look at notebook for why this equation is true
    attack_byte = ord('=') ^ ( ord('?') ^ c[1][5])
    c[1][5] = attack_byte
        
    ans = decrypt_general_purpose_CBC(flatten_list_of_lists(c),
                                      nonce,
                                      AES_single_block,
                                      AES_BLOCK_SIZE,
                                      key)

    decoded = [list_to_string(i) for i in ans] 
    decoded = "".join(flatten_list_of_lists(decoded))      
    print('admin= as present?')
    print('admin=' in decoded)
    print()
        
def escape_them_characters(new_payload):

    '''
    Replacing with a question mark
    '''
    return "".join([i if i !=';' and i != '=' else '?'.format(i) for i in new_payload])
    
if __name__ == '__main__':

    # print(lab)
    # print()
    # print([i for i in x])
    # challenge11()
    # challenge12()
    # challenge13()
    # challenge15()
    challenge16()    
          
