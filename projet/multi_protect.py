import sys
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Hash import SHA256


#def cipherasym(filein, fileout, my_rsa_priv_sign, my_rsa_pub_cipher, *buffers):
def cipherasym(filein, fileout, my_rsa_priv_sign, my_rsa_pub_cipher, usr_rsa_pub_cipher):
	data = ""
	with open(filein, "rb") as f:
		data = f.read()

	# My RSA sign cle priv
	rsa_priv_sign = RSA.import_key(open(my_rsa_priv_sign).read())
	sign_priv_key = pss.new(rsa_priv_sign)

	# My RSA chiffre cle pub
	rsa_pub_key = RSA.importKey(open(my_rsa_pub_cipher).read())
	cipher_pub_key = PKCS1_OAEP.new(rsa_pub_key)

	# USER 1 RSA chiffre cle pub
	rsa_usr_pub_key = RSA.importKey(open(usr_rsa_pub_cipher).read())
	cipher_usr_pub_key = PKCS1_OAEP.new(rsa_usr_pub_key)

	# kc
	kc = get_random_bytes(32)

	# iv
	iv = get_random_bytes(16)

	# Chiffrement AES-CBC
	cipher = AES.new(kc, AES.MODE_CBC, iv)
	bmsgcipher = cipher.encrypt(pad(data, AES.block_size))

	# Chiffrement RSA cle secrete avec cle publique
	rsa_cipher = cipher_pub_key.encrypt(kc)

	# Chiffrement RSA cle secrete avec cle publique des USERS
	usr_rsa_cipher = cipher_usr_pub_key(kc)

	# generation du hash -> sign(IV || RSA_CIPHER || MSG_CIPHER)
	sha256 = SHA256.new()
	sha256.update(iv)
	sha256.update(rsa_cipher)
	sha256.update(bmsgcipher)

	# generation du hash des USERS -> sign(IV || USR_RSA_CIPHER || MSG_CIPHER)
	usrsha256 = SHA256.new()
	usrsha256.update(iv)
	usrsha256.update(usr_rsa_cipher)
	usrsha256.update(bmsgcipher)

	# signature du hash avec cle privee
	signature = sign_priv_key.sign(sha256)

	with open(fileout, "wb") as f:
		f.write(usrsha256)
		f.write(usr_rsa_cipher)
		f.write(iv)
		f.write(bmsgcipher)
		f.write(signature)
		f.close()


def usage():
	print ("""
	usage: 
  $ python multi_protect.py -e <input_file> <output_file> <my_sign_priv.pem> <my_ciph_pub.pem> [user1_ciph_pub.pem ... [userN_ciph_pub.pem]]

  $ python multi_protect.py -d <input_file> <output_file> <my_priv_ciph.pem> <my_pub_ciph.pem> <sender_sign_pub.pem>
  """)
  
	sys.exit(1)

def main(argv):
	# check arguments
	if len(sys.argv) < 6:
		usage()

#	try:
	if sys.argv[1] == "-e":
		print ("This will encrypt")
		buff = []
		for arg in argv[6:]:
			buff.append(arg)
		#print buff
		#cipherasym( argv[2], argv[3], argv[4], argv[5], buff )
		cipherasym( argv[2], argv[3], argv[4], argv[5], argv[6] )

	elif sys.argv[1] == "-d":
		print ("This will decrypt")

	else:
		usage()

#	except IndexError:
#		print """usage: 
#		$ python multi_protect.py -e <input_file> <output_file> <my_sign_priv.pem> <my_ciph_pub.pem> [user1_ciph_pub.pem ... [userN_ciph_pub.pem]]

#		$ python multi_protect.py -d <input_file> <output_file> <my_priv_ciph.pem> <my_pub_ciph.pem> <sender_sign_pub.pem>"""
#	except ValueError:
#		print "Sorry something went wrong"

if __name__ == "__main__":
	main(sys.argv)
