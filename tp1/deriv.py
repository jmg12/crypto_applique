#import Crypto
import os
import binascii
from struct import pack
from Crypto.Hash import SHA256

def deriv_pwd( mdp, salt, ctr ):
	lenmdp = len(mdp)
	c = 0	
	
	sha256 = SHA256.new()
	bmdp = str.encode(mdp)
	bsalt = str.encode(salt)
	bc = pack("<I",c)
	hashiter = [bmdp, bsalt, bc]
	for h in hashiter:
		sha256.update(h)

	res0 = sha256.digest()
	res = res0
	#while c < ctr:
	for i in range(1,ctr):
		sha256 = SHA256.new()
		# gen salt with Crypto.Random
		#salt = "".join(random.choice(salt) for i in range(lenmdp))

		# creation du salt
		"""
		salt = "".join(chr(random.randint(0,255)) for i in range(len(key)))
		#bsalt = bytearray(salt)
		bsalt = str.encode(salt)
		"""

		sha256.update(res)
		
		bmdp = str.encode(mdp)
		bsalt = str.encode(salt)
		#bc = pack("<I",c)
		bc = pack("<I",i)

		hashiter = [bmdp, bsalt, bc]

		for h in hashiter:
			sha256.update(h)

		res = sha256.digest()
		#c += 1

	return res

test = deriv_pwd("toto", "00000000", 5000)
print(binascii.hexlify(test))
