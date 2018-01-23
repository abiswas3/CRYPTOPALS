import sys
sys.path.append('../')

from utils import *
from cbc import *

import numpy as np
from sklearn.metrics import accuracy_score
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
    
if __name__ == '__main__':
    
    # print(lab)
    # print()
    # print([i for i in x])
    challenge11()
