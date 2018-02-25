import sys
sys.path.append('../')

from utils import *
from rsa import RSA

from Crypto.Random import random

'''I'm going to just simulate this: pretend server already has a hash
and now we have to edit

So the game is send the server a different version of the cipher that
is different from the true cipher the serevr must decrypt; so i send a
random cipher; decrypt that cioher and undo the randomnes i added.

'''

if __name__ == '__main__':

    R = RSA(1024)

    msg = string_to_list('Leighton Baines plays for Everton')
    msg_int = bytes_to_int(msg)

    C = R.encrypt(msg_int)

    n = R.n
    e = R.e

    S = random.randint(0, n)

    # C' = ((S**E mod N) C) mod N

    new_c = (pow(S, e, n)* C) % n

    recover = modular_inverse(S, n)*R.decrypt(new_c) % n

    print(CYAN,'Original : ', 'Leighton Baines plays for Everton' , RESET)
    print(GREEN,'Recovered: ', list_to_string(R.int_to_bytes(recover)), RESET)
