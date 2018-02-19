import sys
sys.path.append('../')

from utils import *
from cbc import *
from ctr import *

if __name__ == '__main__':

    a = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
    pText = [i for i in base64.b64decode(''.join(a))]

    key = string_to_list("YELLOW SUBMARINE")
    nonce = [0]*8 # this should be random

    ans = list_to_string(AES_CTR(pText, key, nonce, encrypt=True))
    print(ans)
