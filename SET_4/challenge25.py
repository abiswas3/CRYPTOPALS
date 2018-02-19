import sys
sys.path.append('../')

from utils import *
from cbc import *
from ctr import *
from SET_1.challenges import challenge7

def edit(ciphertext, key, offset, newtext, nonce=[0]*8):
    '''
    Now, write the code that allows you to "seek" into the ciphertext,
    decrypt, and re-encrypt with different plaintext. Expose this as a
    function, like, "edit(ciphertext, key, offset, newtext)".
    '''

    num_blocks = math.ceil(len(ciphertext) / AES_BLOCK_SIZE)
    
    key_stream = CTR_keystream(num_blocks, key, nonce)

    # If newtext is the plain text I should get the same cipher Text
    newCipherText = key_stream[offset] ^ newtext

    if newCipherText == ciphertext[offset]:
        return True

    return False
    


'''Back to CTR. Encrypt the recovered plaintext from this file (the
ECB exercise) under CTR with a random key (for this exercise the key
should be unknown to you, but hold on to it).'''

print('CHALLENGE 25')
pText = challenge7()
key = generate_AES_key(block_size=16)
nonce = [0]*8

cText = AES_CTR(pText, key, nonce, encrypt=True)


'''
Imagine the "edit" function was exposed to attackers by means of an
API call that didn't reveal the key or the original plaintext; the
attacker has the ciphertext and controls the offset and "new text".

Recover the original plaintext.'''

solved_pText = []
for i in range(len(cText)):
    if i == 100:
        break
    print(i)
    for k in range(256):
        if edit(cText, key, i, k, nonce=nonce):
            solved_pText.append(k)
            break
                        
        
