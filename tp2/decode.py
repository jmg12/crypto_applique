import os
from struct import pack
from Crypto.Hash import SHA256, HMAC
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import random


def decode(filename):
	content = ""
	with open(filename) as f:
		content = f.read()
	try:
		cipher = AES.new(ki, digestmod=SHA256)

	

print(decode(./testout))
