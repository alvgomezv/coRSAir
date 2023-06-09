#!/usr/bin/python3
#!/goinfre/alvgomez/miniconda3/envs/42cyber-alvgomez/bin/python

import argparse
from OpenSSL import crypto
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_v1_5
import random

def gcd(a, b):
    if a == 0:
        return b
    return gcd(b % a, a)

def findModInverse(a, m):
    # Returns the modular inverse of a % m, which is
    # the number x such that a * x % m = 1
    if gcd(a, m) != 1:
        return None # no mod inverse if a & m aren't relatively prime
    # Calculate using the Extended Euclidean Algorithm:
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m

def encrypt_msg(msg, public_key):
    cipher = PKCS1_v1_5.new(public_key)
    emsg = cipher.encrypt(msg)
    return emsg

def decrypt_msg(emsg, private_key):
    sentinel = get_random_bytes(16)
    cipher = PKCS1_v1_5.new(private_key)
    dmsg = cipher.decrypt(emsg, sentinel)
    return dmsg.decode()
 
def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("keys", nargs='*')
    parser.add_argument("-m", type=str, action="store", dest="msg", help="Imput a message to decrypt")
    parser.add_argument("-k", type=str, action="store", dest="key1", help="Imput a public Key")
    arg = parser.parse_args()
    return arg

class corsair:
    def __init__(self):
        self.public_key1 = None
        self.public_key2 = None
        self.p = None
        self.private_key1 = None

    def open_keys(self, key1, key2):
        with open(key1, "rb") as f:
            pem_data1 = f.read()
        self.public_key1 = RSA.importKey(pem_data1)
        with open(key2, "rb") as f:
            pem_data2 = f.read()
        self.public_key2 = RSA.importKey(pem_data2)
    
    def check_gcd(self):
        n1 = self.public_key1.n
        n2 = self.public_key2.n
        if n1 > n2:
            p = gcd(n1, n2)
        else:
            p = gcd(n2, n1)
        if p != 1:
            self.p = p
            return True
        return False
    
    def create_private_key(self, key1):
        n1 = self.public_key1.n
        e1 = self.public_key1.e
        q1 = n1 // self.p
        d1 = findModInverse(e1, (self.p - 1) * (q1 - 1))
        self.private_key1 = RSA.construct((n1, e1, d1, self.p, q1))

if __name__ == "__main__":
    args = parse_arguments()
    crsa = corsair()
    if args.key1:
        key1 = args.key1
        if "pem" not in key1:
            raise Exception("PEM file must be provided")
        flag = 0
        for key2 in args.keys:
            if "pem" in key2 and key1 != key2:
                crsa.open_keys(key1, key2)
                if crsa.check_gcd():
                    print("Match found!")
                    crsa.create_private_key(key1)
                    flag = 1
                    break
        if flag == 0:
            print("No matches found")
        if args.msg:
            if "bin" not in args.msg:
                raise Exception("BIN file must be provided")
            with open(args.msg, "rb") as f:
                data = f.read()
            dmsg = decrypt_msg(data, crsa.private_key1)
            print("Message decrypted:")
            print()
            print(f"    {dmsg}")
    else:
        flag = 0
        vkeys = []
        for key1 in args.keys:
            for key2 in args.keys:
                if "pem" in key1 and "pem" in key2 and key1 != key2:
                    crsa.open_keys(key1, key2)
                    if crsa.check_gcd():
                        if key1 not in vkeys or key2 not in vkeys:
                            if flag == 0:
                                print("Match found! This keys are vulnerable:")
                            print(f"Key: {key1}")
                            print(f"Key: {key2}")
                            vkeys.append(key1)
                            vkeys.append(key2)
                            flag = 1
       
#from Crypto.PublicKey import RSA   
#    
#if __name__ == "__main__":
#    args = parse_arguments()
#    key1 = args.public_key
#    if "pem" in key1:
#        with open(key1, "rb") as f:
#            pem_data1 = f.read()
#        public_key1 = RSA.importKey(pem_data1)
#    flag = 0
#    for key2 in args.keys:
#        if "pem" in key2 and key1 != key2:
#            with open(key2, "rb") as f:
#                pem_data2 = f.read()
#            public_key2 = RSA.importKey(pem_data2)
#            n1 = public_key1.n
#            n2 = public_key2.n
#            if n1 > n2:
#                p = gcd(n1, n2)
#            else:
#                p = gcd(n2, n1)
#            if p != 1:
#                flag = 1
#                break
#
#    if flag == 0:
#            print("No matches found")
#    else:
#        n1 = public_key1.n
#        e1 = public_key1.e
#        q1 = n1 // p
#        d1 = findModInverse(e1, (p - 1) * (q1 - 1))
#        private_key = RSA.construct((n1, e1, d1, p, q1))
#        dmsg = decrypt_msg(args.emsg, private_key)
#        print(dmsg)
