import binascii
import codecs
import array
import collections
import sys
import numpy as np

def hex_to_list(a):

    s=binascii.unhexlify(a)
    b=[x for x in s]
    return b

def list_to_hex(array_alpha):
    return ''.join('{:02x}'.format(x) for x in array_alpha)

def list_to_english(s):
    a = [chr(x) for x in s]
    return ''.join(a)

def english_to_list(s):
    return [ord(i) for i in s]
    
def hex_to_64(h):
    hex = codecs.decode(h, "hex")
    base = binascii.b2a_base64(hex).strip()
    return base

def xor(s1,s2):
    '''
    Takes input in HEX
    '''    
    a = hex_to_list(s1)
    b = hex_to_list(s2)

    l = [(i ^ j) for i,j in zip(a,b)]

    return l

def xor_encoded_cipher(s):

    l = hex_to_list(s) # convert hex to list of bytes    
    l = list_to_english(l) # convert that list of bytes to english word
    
    # xor with each i and do frequency analysis
    scores = []
    start = 0
    end = 500
    for i in range(start,end):
        buffer = [i for x in l]
        buffer = list_to_hex(buffer)
        decode = list_to_english(xor(s,buffer))
        c = frequency_analysis(decode)
        print(decode)
        scores.append(c)
        # if c < float('inf'):
        #     print(c,i)
        #     print(decode)

    # output best version
    i = np.argmin(scores)+ start
    buffer = [i for x in l]
    buffer = list_to_hex(buffer)
    decode = list_to_english(xor(s,buffer))
    
    print(decode)
    return decode

def challenge4():

    with open('challenge4.txt') as f:

        a = f.readlines()

    return a
    
def frequency_analysis(l, epsilon=0.1):

    punctuations = ['.',
                    ',',
                    "'",
                    '!',
                    '?',
                    ':',
                    '"',
                    ')',
                    '(',
                    ' ']
    
    l = l.lower()
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
        'z':0.1
    }
    letters = collections.Counter(l)

    count = 0
    for key in letters.keys():
        if key in freq.keys():
            count += (abs(letters[key]/len(l)*100-freq[key]))
        elif key in punctuations:
            continue
        else:
            return float('inf')
        
    return count
    
    

    
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
