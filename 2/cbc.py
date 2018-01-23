import sys
sys.path.append('../')
from utils import *

from Crypto.Cipher import AES
from Crypto import Random
import array

def encrypt_general_purpose_CBC(plain_text, nonce, f, block_size, key):

    '''
    plain_text : list of bytes
    nonce : C0
    f: encryption function(for example AES)
    '''

    blocks = make_pkcs7_padded_block_matrix(plain_text, block_size)

    old_cipher = nonce
    encrypted_text = []

    for block in blocks:
        Y_i = xor_byte_arrays(block, old_cipher)
        c_i = f(Y_i, key, encrypt=True)        
        encrypted_text.append(c_i)        
        old_cipher = c_i
        
    return encrypted_text

def decrypt_general_purpose_CBC(cipher_text,
                                nonce,
                                f,
                                block_size,
                                key):

    '''
    '''

    blocks = make_pkcs7_padded_block_matrix(cipher_text, block_size)
    old_cipher = nonce
    
    decrypted_text = []
    
    for block in blocks:        
        decrypted_text.append(xor_byte_arrays(f(block, key, encrypt=False),
                                              old_cipher))        
        old_cipher = block
        
    return decrypted_text


def AES_single_block(text, key, encrypt=False):

    key = array.array('B', key).tobytes()
    cipher = AES.new(key)    

    t = array.array('B', text).tobytes()
    
    if not encrypt:
        return [i for i in cipher.decrypt(t)]
        
    return [i for i in cipher.encrypt(t)]

def AES_ECB(text, key, encrypt=False):

    key = array.array('B', key).tobytes()
    cipher = AES.new(key, AES.MODE_ECB)    

    t = array.array('B', text).tobytes()    
    if not encrypt:
        return cipher.decrypt(t)
        
    return cipher.encrypt(t)


if __name__ == '__main__':

    pass
