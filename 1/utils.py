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
    s = binascii.unhexlify(a)
    b = [x for x in s]
    
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

# THIS IS SURPLUS
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
