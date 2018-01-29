import binascii
import base64
import array
import numpy as np

'''CRYPTOPALS RULE: Always operate on raw bytes, never on encoded
strings. Only use hex and base64 for pretty-printing.

To convert between one representation of memory to another. The
best way is to convert it to an intermediate representation we
understand well and can perform operations on it.

That intermediate representation is a list of bytes or a python byte array: 
Same business with the way I'm writing it.

'''
def flatten_list_of_lists(a):

    return [j for i in a for j in i]

def string_to_list(s):
    '''Takes a human readable string and converts it to a list of bytes.
    Remember all a human readable string is a sequence of bytes(chars).
    '''
    return [ord(i) for i in s]


def hex_to_list(a):
    
    '''Example: Convert 1 byte in hex representation to 1 byte in base 10
    HEX : AC Base-10: 12*(16**0) + 10*(16**1)

    Now take a hex string: AC72
    How does it look as a byte array : [172, 114]

    Assume a comes in as a string representation on python

    '''
    
    s = binascii.unhexlify(a)
    b = [int(x) for x in s]

    return b

def base64_to_list(data):
    '''Convert a base64 string to a list of bytes.
    This isn't that different form hex to list of bytes. 

    * In fact 1 hex literals represents 4/8 bytes

    * 1 base-64 literal represents 6/8 bytes.

    So the only real issue that comes is padding when the string isn't
    square of 2. We let the python library code handle it for us .

    Example:
    base64 input: 0EUk
    decimal output: 4*(16**2)+ 20*(16**1)+36*(16**0) = 1380

    The idea is you express the whole bloody thing as binary
    then pick out the first 8 bytes, and so on. The 0 is padded 
    to make it a multiple of 8.
    base64 input: Uk
    k=36: 100010
    U=20: 010100
    Uk = 00000101 00100010
    byte_array: [5, 34]

    Cos i'll pad it to be a multiple of 4: there will an extra 0
    
    '''

    missing_padding = len(data) % 4
    
    if missing_padding != 0:
        data= (4 - missing_padding)*'A' + data

    hex_string = base64.b64decode(data)

    # get list of bytes representation
    return [ i for i in hex_string]


def list_to_hex(lst):
    '''
    List of bytes to hex string

    '''
    message = ''.join('{:02x}'.format(x) for x in lst)
    return message


def list_to_string(lst):
    '''
    Take a list of bytes and convert into ASCII string
    '''
    a = [chr(x) for x in lst]
    return ''.join(a)


def list_to_base64(lst):

    lst = array.array('B', lst)
    return base64.b64encode(lst).decode("utf-8")

def xor_byte_arrays(a,b):

    ans = [(i^j) for i,j in zip(a,b)]

    return ans



def hamming_distance_two_byte_arrays(s1, s2):
    '''Takes two byte arrays and returns the edit distance between them
    i.e the number of bits thaat are different
    '''
    ans = [(i ^ j) for i,j in zip(s1,s2)]
    c = 0    
    for i in ans:
        c += count_ones(i)
        
    return c


def count_ones(v):
    '''
    Count number of 1's in bin represenation of c
    '''
    c = 0
    while v > 0:
        c += v & 1
        v = v //2
        
    return c

def flatten(l):

    return [item for sublist in l for item in sublist]


def transpose(byte_mat):

    mat = []
    for row in byte_mat[0]:
        mat.append([])

    for i,row in enumerate(byte_mat):
        for j, col in enumerate(row):
            mat[j].append(col)
                        
    return mat

def make_blocks(byte_arr,
                key_size):

    if len(byte_arr) % key_size == 0:
        n = len(byte_arr)//key_size
    else:
        n = len(byte_arr)//key_size + 1
    
    
    byte_mat = [ byte_arr[ i*key_size: (i+1)*key_size] for i in range(n)]

    return byte_mat 


def hamming_distance_rows(byte_mat):

    '''
    Return the average hamming distance between two rows 
    of byte_matrix.

    A byte_matrix is the cipher text split up into key size rows
    '''

    num_rows = len(byte_mat)
    key_size = len(byte_mat[0])

    if num_rows < 2:
        return -1

    elif num_rows < 4:
        # average first 2 rows
        
        s1 = byte_mat[0]
        s2 = byte_mat[1]
    
        return hamming_distance_two_byte_arrays(s1, s2)/key_size

    else:

        # average first four guys
        count = 0
        ham_score = 0
        for i in range(4):
            for j in range(4):
                if i != j:
                    s1 = byte_mat[i]
                    s2 = byte_mat[j]
                
                    ham_score += hamming_distance_two_byte_arrays(s1, s2)/key_size
                    count +=1 

        return ham_score/count
    

def pkcs7(lst_of_bytes, block_size):

    '''
    Pad lst_of_bytes using the pkcs7 algorithm.


    Return padded list of bytes.
    '''

    # an entire block of full padding if it's padded
    if len(lst_of_bytes) % block_size == 0:
        return lst_of_bytes + [block_size for i in range(block_size)]

    diff = block_size - (len(lst_of_bytes) % block_size)
    
    return lst_of_bytes + [ diff for i in range(diff)]

def make_pkcs7_padded_block_matrix(byte_arr, block_size):

    # pad if need be
    byte_arr = pkcs7(byte_arr, block_size)

    
    return [byte_arr[i*block_size:(i+1)*block_size] for i in range(len(byte_arr)//block_size)]


def cookie_to_JSON(cookie):

    #Write a k=v parsing routine, as if for a structured cookie.

    if len(cookie.split('&')) > 0:
        key_vals = [i.split('=') for i in  cookie.split('&') if len(i.split('=')) == 2]
        return {key:val for key,val in key_vals}
        
    else:
        return {}
    
def JSON_to_cookie(x):
    
    return '&'.join(['{}={}'.format(key, val) for key, val in x.items()])

def profile_for(email):

    if '&' in email or '=' in email:
        return None

    return {'email': email,
            'uid': 10,
            'role': 'user'
    }

def verify_pkcs7(padded_text):
    
    f = lambda s:s[-1:]*s[-1]==s[-s[-1]:]
    
    return f(padded_text)

def strip_pkcs7(padded_text, block_size=16):

    pads = block_size - padded_text[-1]
    
    return padded_text[: pads]
    
if __name__ == '__main__':

    # ###################################################
    # # string- list :Test
    # ###################################################
    # print('string <=> list :Test')
    # inp = 'AC'
    # exp = [65, 67]    
    # ans = string_to_list(inp)
    # correct = True
    # for i,j in zip(exp,ans):
    #     if i !=j:
    #         correct = False    
    # print('=> Did the answers match up? {}'.format(correct))

    # inp, exp = exp, inp
    # ans = list_to_string(inp)
    # for i,j in zip(exp,ans):
    #     if i !=j:
    #         correct = False    
    # print('<= Did the answers match up? {}\n'.format(correct))

        
    # ###################################################
    # # hex_to_list :Test
    # ###################################################
    # print('hex <=> list :Test')
    # inp = 'ac72'
    # exp = [172, 114]    
    # ans = hex_to_list(inp)
    # correct = True
    # for i,j in zip(exp,ans):
    #     if i !=j:
    #         correct = False    

    # print('=> Did the answers match up? {}'.format(correct))
    # inp, exp = exp, inp
    # ans = list_to_hex(inp)
    # for i,j in zip(exp,ans):
    #     if i !=j:
    #         correct = False    
    # print('<= Did the answers match up? {}\n'.format(correct))


    
    # ###################################################
    # # base64_to_list :Test
    # ###################################################
    # print('base64 <=> list :Test')
    # inp = 'AAUk'
    # exp = [0,5,36]    
    # ans = base64_to_list(inp)
    # correct = True
    # for i,j in zip(exp,ans):
    #     if i !=j:
    #         correct = False    

    # print('=> Did the answers match up? {}'.format(correct))

    # inp, exp = exp, inp
    # ans = list_to_base64(inp)
    # for i,j in zip(exp,ans):
    #     if i !=j:
    #         correct = False    
    # print('<= Did the answers match up? {}\n'.format(correct))
    


    # ###################################################
    # # Staggered matrix transpose test
    # ###################################################
    # a = [[2, 1], [3, 4], [5, 6], [7]]
    # b = transpose(a)

    # #==============TEST TO SEE IF it works====================
    # s1 = string_to_list('this is a test')
    # s2 = string_to_list('wokka wokka!!!')
    # print(hamming_distance_two_byte_arrays(s1, s2))
    # #==========================================================

    # ###################################################
    # # PKCS#7 test
    # ###################################################

    # lst_of_bytes = string_to_list("YELLOW SUBMARINE")
    # block_size = 20
    # x = pkcs7(lst_of_bytes, block_size)
    # print(x)

    # byte_array = string_to_list("YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE")
    # block_size = 20
    # x = make_pkcs7_padded_block_matrix(byte_array, block_size)
    # print(x)

    # cookie = 'foo=bar&baz=qux&zap=zazzle'
    # x = cookie_to_JSON(cookie)
    pass
