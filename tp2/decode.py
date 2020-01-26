import os
import binascii
from struct import pack
from Crypto.Hash import SHA256, HMAC
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def decode(filename, fkey):
	with open(filename, "rb") as f:
		content = f.read()
	
	with open(fkey, "rb") as k:
		key = k.read()
	
	# Gen Kc pour AES et Ki pour hmac
	kc = SHA256.new(key + pack("<B", 0)).digest()
	ki = SHA256.new(key + pack("<B", 1)).digest()

	# Parsing IV, salt, msgcipher, hmac
	iv = content[0:16]
	salt = content[16:24]
	bmsgcipher = content[24:40]
	bhmac = content[40:72]
	print ("iv = ", binascii.hexlify(iv))
	print ("salt = ", binascii.hexlify(salt))
	print ("bmsgcipher = ", binascii.hexlify(bmsgcipher))
	print ("bhmac = ", binascii.hexlify(bhmac))


	# validation HMAC
	hmac = HMAC.new(ki, digestmod=SHA256)
	hmac.update(iv)
	hmac.update(salt)
	hmac.update(bmsgcipher)
	try:
		hmac.verify(bhmac)
		print("le message est valide\nVous pouvez déchiffrer le message!\n")
	except ValueError:
		print("Le message a été compromis")

	# dechiffrement du message
	try:
		print("Déchiffrement en cours ...")
		cipher = AES.new(kc, AES.MODE_CBC, iv)
		decodemsg = unpad(cipher.decrypt(bmsgcipher),AES.block_size)
		print("Le message secret est : ",decodemsg.decode("utf-8"))

	except ValueError:
		print("Le déchiffrement n'a pas pu aboutir :/")
	

decode("./testout", "./key")
