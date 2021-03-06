import sys
sys.path.append('../')
from utils import *

from Crypto.Cipher import AES
from Crypto import Random
import array

AES_BLOCK_SIZE = 16

def generate_AES_key(block_size=AES_BLOCK_SIZE):

    return np.random.randint(0,
                             size=block_size,
                             high=255).tolist()


def encrypt_general_purpose_CBC(plain_text, nonce, f, block_size, key):

    '''
    plain_text : list of bytes
    nonce : C0
    f: encryption function(for example AES)
    '''

    plain_text = pkcs7(plain_text, block_size)    
    blocks = block_matrix(plain_text, block_size)

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
    Always expect correct padding
    '''
    blocks = block_matrix(cipher_text, block_size)
    c_prev = nonce

    decrypted_text = []
    for c_i in blocks:
        #d(c_i)
        d_c_i = f(c_i, key, encrypt=False)
        
        decrypted_text.append(xor_byte_arrays(d_c_i, c_prev))
        
        c_prev = c_i

    return decrypted_text


def AES_single_block(text, key, encrypt=False):

    key = array.array('B', key).tobytes()
    cipher = AES.new(key)

    t = array.array('B', text).tobytes()

    if not encrypt:
        return [i for i in cipher.decrypt(t)]

    return [i for i in cipher.encrypt(t)]

def AES_ECB(text,
            key,
            encrypt=False,
            block_size=AES_BLOCK_SIZE):

    if len(text) % block_size != 0:
        text = pkcs7(text, block_size)

    key = array.array('B', key).tobytes()
    cipher = AES.new(key, AES.MODE_ECB)

    t = array.array('B', text).tobytes()
    if not encrypt:
        return cipher.decrypt(t)

    return cipher.encrypt(t)

if __name__ == '__main__':

    pass
