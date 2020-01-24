from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.PublicKey import RSA


def cipherasym( filein, fileout, rsa_priv_sign, rsa_pub_cipher ):
	content = ""
	with open(filein, "rb") as f:
		content = f.read()	

	#RSA sign cle priv
	rsa_priv_sign = RSA.import_key(open(rsa_priv_sign).read())
	sign_priv_key = pss.new(rsa_priv_sign)

	# RSA chiffre cle pub
	rsa_pub_key = RSA.importKey(open(rsa_pub_cipher).read())
	cipher_pub_key = PKCS1_OAEP.new(rsa_pub_key)

	# kc
	kc = get_random_bytes(32)

	# iv
	iv = get_random_bytes(16)
	
	# Chiffrement AES-CBC
	cipher = AES.new(kc, AES.MODE_CBC, iv)
	bmsgcipher = cipher.encrypt(pad(content, AES.block_size))

	# Chiffrement RSA
	rsa_cipher = cipher_pub_key.encrypt(kc)

	# generation du hash -> sign(IV || WRAP || C)
	sha256 = SHA256.new()
	sha256.update(iv)
	sha256.update(rsa_cipher)
	sha256.update(bmsgcipher)
	
	# signature du hash
	signature = sign_priv_key.sign(sha256)

	with open(fileout, "wb") as f:
		f.write(iv)
		f.write(rsa_cipher)
		f.write(bmsgcipher)
		f.write(signature)
		f.close()

test = cipherasym( "./testin", "./testout", "rsa_priv.pem","rsa_pub.pem" )