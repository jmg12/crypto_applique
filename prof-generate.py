# gen password
import string
import random

def gen_password(length, alphabet):
    passwd = ""
    for i in range(length):
        passwd += random.choice(alphabet)
    #return passwd
    
    return "".join(random.choice(alphabet) for i in range(length))

