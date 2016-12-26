import binascii
import codecs
import array
import collections
import sys
import numpy as np
import base64
import itertools
from Crypto.Cipher import AES
from Crypto import Random

def hex_to_list(a):
    '''
    Hex string to list of bytes
    '''
    s=binascii.unhexlify(a)
    b=[x for x in s]
    return b

def list_to_byte_string(lst):
    
    return array.array('B', lst).tostring()
    
def list_to_hex(array_alpha):
    '''
    List of bytes to hex string
    '''
    message = ''.join('{:02x}'.format(x) for x in array_alpha)
    return message

def list_to_english(s):
    '''
    Take a list of bytes and convert into ASCII string
    '''
    a = [chr(x) for x in s]
    return ''.join(a)

def english_to_list(s):
    '''
    Take english text and convert it to a list of bytes
    '''
    return [ord(i) for i in s]
    
def hex_to_64(h):
    '''
    Hex to base 64
    '''
    hex = codecs.decode(h, "hex")
    base = binascii.b2a_base64(hex).strip()
    return base

def base64_to_list(h):
    '''
    base64_to_hex
    '''
    hex_string = base64.b64decode(h)

    return [ i for i in hex_string]

def xor(s1,s2):
    '''
    Takes input in HEX and returns a xored
    answer as list of bytes
    '''
    a = hex_to_list(s1)
    b = hex_to_list(s2)

    l = [(i ^ j) for i,j in zip(a,b)]

    return l

def xor_byte_array(a, b):
    '''
    Takes input in list of bytes and returns a xored
    answer as list of bytes
    '''

    l = [(i ^ j) for i,j in zip(a,b)]
    return l

def xor_encoded_cipher(s):
    '''
    Decodes a xor encoded cipher using frequency analysis.
    Takes in list of bytes and outputs plain text
    and the score of plain text 
    '''
    
    # convert that list of bytes to english word for freq analysis    
    l = list_to_english(s)
    
    # xor with each i and do frequency analysis
    scores = []
    start = 0
    end = 256
    
    for i in range(start,end):
        buffer = [i for x in l]
        decode = list_to_english(xor_byte_array(s,buffer))
            
        c = frequency_analysis(decode)
        scores.append(c)
            
    # output best version
    i = np.argmin(scores)+ start
    buffer = [i for x in l]
    decode = xor_byte_array(s,buffer)
        
    
    return decode

def frequency_analysis(l, epsilon=0.1):

    '''
    Takes in ascii string and outputs a score
    based on frequency analysis.

    The closer to the score to 0 the more similar 
    it is to the english language.
    '''
    punctuations = ['.',
                    ',',
                    "'",
                    '!',
                    '?',
                    ':',
                    '"',
                    ')',
                    '(',
                    ' ',
                    '\n']
    
    freq = {
        'a':8.2,
        'b':1.5,
        'c':2.8,
        'd':4.3,
        'e':12.7,
        'f':2.2,
        'g':2.0,
        'h':6.1,
        'i':7.0,
        'j':0.2,
        'k':0.8,
        'l':4.0,
        'm':2.4,
        'n':6.7,
        'o':7.5,
        'p':1.9,
        'q':0.1,
        'r':6.0,
        's':6.3,
        't':9.1,
        'u':2.8,
        'v':1.0,
        'w':2.4,
        'x':0.2,
        'y':2.0,
        'z':0.1,
        'A':8.2,
        'B':1.5,
        'C':2.8,
        'D':4.3,
        'E':12.7,
        'F':2.2,
        'G':2.0,
        'H':6.1,
        'I':7.0,
        'J':0.2,
        'K':0.8,
        'L':4.0,
        'M':2.4,
        'N':6.7,
        'O':7.5,
        'P':1.9,
        'Q':0.1,
        'R':6.0,
        'S':6.3,
        'T':9.1,
        'U':2.8,
        'V':1.0,
        'W':2.4,
        'X':0.2,
        'Y':2.0,
        'Z':0.1
        
    }
    letters = collections.Counter(l)

    count = 0
    for key in letters.keys():
        if key in freq.keys():
            count += (abs(letters[key]/len(l)*100-freq[key]))
        elif key in punctuations:
            continue
        else:
            count += 10
        
    return count
    
    
def challenge4():
    '''
    Take in a bunch of strings and 
    output the only one that was single block xor encoded.
    '''
    with open('challenge4.txt') as f:
        a = f.readlines()
        
    a = [i.strip() for i in a]
    
    scores = []
    words = []
    for s in a:
        word, score = xor_encoded_cipher(s)
        scores.append(score)
        words.append(word)

    print(words[np.argmin(scores)])
    return a
    
def challenge5(message, key):
    '''
    Takes in ascii string and encode it with
    block xor using key.
    '''
    message_byte_form = english_to_list(message)
    
    pad = [ord(key[i % len(key)]) for i in range(len(message))]
    
    # print( [(i,j) for i,j in zip(message_byte_form, pad)])

    ans = xor_byte_array(message_byte_form, pad)

    return list_to_hex(ans)

def aes_ecb_mode(message, key, encrypt=True):

    '''

    '''
    if len(message) % 16 != 0:
        return None

    ans = []
    for i in range(len(message)//16):
        start = i*16
        end = (i+1)*16

        if encrypt:
            p = message[start:end]
            c = encrypt_single_block(p, key)
        else:
            c = message[start:end]
            p = encrypt_single_block(c, key, encrypt=False)
            ans.append(p)
            
    return b''.join(ans)

def encrypt_single_block(p, key, encrypt=True):
    '''
    Encrypt using AES-128
    '''
    cipher = AES.new(key, AES.MODE_ECB)
    if encrypt:
        c = cipher.encrypt(p)
    else:
        c = cipher.decrypt(p)
        
    return c

def challenge7(c,k):

    cipher = AES.new(k, AES.MODE_ECB)
    p = cipher.decrypt(c)
    return p


def challenge8():
    with open('challenge8.txt') as f:
        a = f.readlines()        
    a = [i.strip() for i in a]
    a = [hex_to_list(i) for i in a]

    count_arr = []
    for i in a:            
        if len(i) % 16 != 0:
            continue

        cipher_text = []
        for j in range(len(i)//16):
            start = j*16
            end = (j+1)*16
            block = list_to_hex(i[start:end])
            cipher_text.append(block)
            
        count_arr.append(len(np.unique(cipher_text)))

    print(np.argmin(count_arr), "he's my guy")
        
      
def hamming_distance_two_strings(s1, s2):

    ans = [(i ^ j) for i,j in zip(s1,s2)]
    
    c = 0
    for i in ans:
        c += count_bits(i)
    
    return c
    
def count_bits(v):

    c = 0
    while v > 0:
        c += v & 1
        v = v //2
        
    return c

def hamming_score_for_given_key_size(s, k, index=0):

    count = 0
    start = 0
    end = k
    s1 = s[start:end]
    
    start = k
    end = 2*k
    s2 = s[start:end]
    
    count += hamming_distance_two_strings(s1, s2)/k

    start = k
    end = 2*k
    s1 = s[start:end]
    
    start = 2*k
    end = 3*k
    s2 = s[start:end]

    
    count += hamming_distance_two_strings(s1, s2)/k

    start = 3*k
    end = 4*k
    s1 = s[start:end]
    
    start = k
    end = 2*k
    s2 = s[start:end]

    count += hamming_distance_two_strings(s1, s2)/k

    start = 4*k
    end = 5*k
    s1 = s[start:end]
    
    start = 5*k
    end = 6*k
    s2 = s[start:end]
    
    count += hamming_distance_two_strings(s1, s2)/k
        
    return count
    
def find_key_size(s, index=0):
    arr = []
    for k in range(2,40):
        arr.append(hamming_score_for_given_key_size(s, k, index))
        
    arr = np.array(arr)
    inds = np.argsort(arr)
    return inds, arr

def transpose(s, key_size):
    
    final_arr = []
    for i in range(key_size):
        final_arr.append([])
        
    for i in range(len(s)):
        final_arr[i % key_size].append(s[i])
            
    return final_arr
        
if __name__ == '__main__':

    # challenge 1
    # print('Challenge 1')
    # h ='49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    # s = hex_to_64(h)
    # print(s)
    # print()
    
    # challenge 2
    # print('Challenge 2')    
    # a = '1c0111001f010100061a024b53535009181c'
    # b = '686974207468652062756c6c277320657965'

    # print(list_to_hex(xor(a,b)))

    # challenge 3
    print('Challenge 3')
    s = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    xor_encoded_cipher(s)

    # challenge 4
    # print('Challenge 4')    
    # a = challenge4()

    # challenge 5
    # s = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    # k = 'ICE'
    # ans = challenge5(s,k)
    # expected_ans = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    # count = 0
    # for i,j in zip(ans, expected_ans):
    #     if i !=j:
    #         print('{}: {},{}'.format(count, i,j))
    #     count +=1
    # print(ans == expected_ans)

    #Challenge 6
    # s1 = 'this is a test'
    # s2 = 'wokka wokka!!!'
    # # print(hamming_distance_two_strings(s1.encode(), s2.encode()))    
    # with open('challenge6.txt') as f:
    #     a = f.readlines()        
    # a = [base64_to_list(i) for i in a]
    # # # flattem array
    # a = list(itertools.chain(*a))
    # inds, arr = find_key_size(a)
    # key_size_options = 2 + inds[:4]

    
    # BIG_SOL = []
    # for key_size in key_size_options:
    #     SOLN = []
    #     a1 = transpose(a,key_size)
    #     for cipher in a1:
    #         SOLN.append(xor_encoded_cipher(cipher))
    #     BIG_SOL.append(SOLN)


    # # Have len(BIG_SOL) number of solutions, need the best one
    # K = -1
    # s = BIG_SOL[K]
    # # Make string of them
    # word = ''
    # arr = [len(k) for k in s]
    # for i in range(99):
    #     for j in range(len(s)):
    #         print(j,i)
    #         word += chr(s[j][i])

    # print(word)

                        
    # challenge 7
    # with open('challenge7.txt') as f:
    #     a = f.readlines()        
    # a = [i.strip() for i in a]
    
    # message = ''.join(a) # base64 string
    # bas64 to byte string ( same thing as list of bytes)
    # message = base64.b64decode(message)    
    # key = b'YELLOW SUBMARINE'    
    # # p = challenge7(message, key)
    # p = aes_ecb_mode(message, key, encrypt=False)

    # Challenge 8
    # challenge8()    

    
