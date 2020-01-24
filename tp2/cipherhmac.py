import os
#import binascii
from struct import pack
from Crypto.Hash import SHA256, HMAC
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
#from base64 import b64encode
import random

def deriv_pwd( mdp, salt, ctr ):

	sha256 = SHA256.new()
	bmdp = str.encode(mdp)
	bsalt = str.encode(salt)
	bc = pack("<I",0)
	hashiter = [bmdp, bsalt, bc]

	for h in hashiter:
		sha256.update(h)

	res0 = sha256.digest()
	res = res0

	for i in range(1,ctr):
		sha256 = SHA256.new()
		sha256.update(res)
		bmdp = str.encode(mdp)
		bsalt = str.encode(salt)
		bc = pack("<I",i)
		hashiter = [bmdp, bsalt, bc]

		for h in hashiter:
			sha256.update(h)

		res = sha256.digest()
	return res

def cipherhmac( mdp, filein, fileout ):
	content = ""
	with open(filein, "rb") as f:
		content = f.read()	
	
	salt = "".join(chr(random.randint(0,255)) for i in range(len(mdp)))

	key = deriv_pwd( mdp, salt, 5000 )

	#bsalt = bytearray(salt)
	bsalt = str.encode(salt)

	#creation des deux keys
	# kc
	sha256 = SHA256.new()
	sha256.update(key)
	sha256.update(pack("B",0))
	kc = sha256.digest()
	# ki
	sha256 = SHA256.new()
	sha256.update(key)
	sha256.update(pack("B",1))
	ki = sha256.digest()
	
	#Chiffrement AES-CBC
	cipher = AES.new(kc, AES.MODE_CBC)	
	bmsgcipher = cipher.encrypt(pad(content, AES.block_size))
	iv = cipher.iv
	
	#Gen hmac
	hmac = HMAC.new(ki, digestmod=SHA256)
	hmac.update(iv)
	hmac.update(bsalt)
	hmac.update(bmsgcipher)
	bhmac = hmac.digest()

	with open(fileout, "wb") as f:
		f.write(iv)
		f.write(bsalt)
		f.write(bmsgcipher)
		f.write(bhmac)

	#foutput = open(fileout, "wb+")
	#foutput.write(iv+bsalt+bmsgcipher+bhmac)
	#foutput.write(bhmac)
	#foutput.close()

test = cipherhmac("toto", "./testin", "./testout")
