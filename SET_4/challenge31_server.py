import sys
sys.path.append('../')

from utils import *

from flask import Flask, render_template, session, request

import random
from time import sleep

from h_mac import hmac

delay = 0.05
key = b"YELLOW_SUBMARINE"
app = Flask(__name__)
app.config['SECRET_KEY'] = str(random.random())


def insecure_equals(s1, s2):
    """Implements the == operation by doing byte-at-a-time comparisons with early exit
    (ie, return false at the first non-matching byte). Sleeps 50ms after each byte.
    """
    for b1, b2 in zip(s1, s2):
        if b1 != b2:
            return False

        sleep(delay)
        
    return True
                                            
@app.route('/test', methods=['GET'])
def index():

    digest = hmac(key,
                  request.args.get('file').encode(),
                 "SHA1")
    
    signature = request.args.get('signature').encode()

    
    if insecure_equals(digest, signature):
        return "OK", 200

    else:
        return "BAD", 500
            
    
if __name__ == '__main__':

    app.run(port=8000)
        
