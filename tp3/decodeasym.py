from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.PublicKey import RSA
import binascii

#def decode( filename, fkey, rsa_pub_sign, rsa_priv_cipher ):
def decode( filename, rsa_pub_sign, rsa_priv_cipher ):
	with open(filename, "rb") as f:
		content = f.read()

	# RSA sign cle pub
	rsa_pub_sign = RSA.import_key(open(rsa_pub_sign).read())
	sign_pub_key = pss.new(rsa_pub_sign)

	# RSA dechiffre cle priv
	rsa_priv_key = RSA.importKey(open(rsa_priv_cipher).read())
	cipher_priv_key = PKCS1_OAEP.new(rsa_priv_key)

	# Parsing IV, rsa_cipher, bmsgcipher, signature
	iv = content[0:16]
	rsa_cipher = content[16:272]
	bmsgcipher = content[272:288]
	signature = content[288:544]

	print ("iv = ", binascii.hexlify(iv), "\n")
	print ("rsa cipher = ", binascii.hexlify(rsa_cipher), "\n")
	print ("msg cipher = ", binascii.hexlify(bmsgcipher), "\n")
	print ("signature = ", binascii.hexlify(signature), "\n")

	# Recuperation de la cle master
	kc = cipher_priv_key.decrypt(rsa_cipher)

	# validation du hash
	sha256 = SHA256.new()
	sha256.update(iv)
	sha256.update(rsa_cipher)
	sha256.update(bmsgcipher)

	try:
		sign_pub_key.verify(sha256,signature)
		print("Le message est valide\nVous pouvez déchiffrer le message!\n")

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


#decode("./testout", "./secretekey", "rsa_pub.pem", "rsa_priv.pem")
decode("./testout", "rsa_pub.pem", "rsa_priv.pem")
