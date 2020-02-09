import sys
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Hash import SHA256
import binascii
import struct


def cipherasym(filein, fileout, my_rsa_priv_sign, my_rsa_pub_cipher, *buffers):
	data = ""
	with open(filein, "rb") as f:
		data = f.read()

	# Recuperation des arguments du buffers
	arguments = ()
	for buf in buffers:
		arguments = buf
	
	# Recuperation des cle RSA pub des ustilisateurs 
	usrsRSApub = []
	for i in range(0,len(arguments)):
		usrsRSApub.append(arguments[i])

	# My RSA sign cle priv
	rsa_priv_sign = RSA.import_key(open(my_rsa_priv_sign).read())
	sign_priv_key = pss.new(rsa_priv_sign)

	# My RSA chiffre cle pub
	rsa_pub_key = RSA.importKey(open(my_rsa_pub_cipher).read())
	cipher_pub_key = PKCS1_OAEP.new(rsa_pub_key)

	# USERS RSA chiffre cle pub
	cipher_usrs_pub_key = []
	for i in range(0,len(usrsRSApub)):
		rsa_usr_pub_key = RSA.importKey(open(usrsRSApub[i]).read())
		cipher_usrs_pub_key.append(PKCS1_OAEP.new(rsa_usr_pub_key))

	# kc
	kc = get_random_bytes(32)

	# iv
	iv = get_random_bytes(16)

	# Chiffrement AES-CBC
	print("Chiffrement en cours ...")
	cipher = AES.new(kc, AES.MODE_CBC, iv)
	bmsgcipher = cipher.encrypt(pad(data, AES.block_size))

	# Chiffrement RSA cle secrete avec cle publique
	rsa_cipher = cipher_pub_key.encrypt(kc)

	# Chiffrement RSA cle secrete avec cle publique des USERS
	usrs_rsa_cipher = []
	for i in range(0,len(cipher_usrs_pub_key)):
		usrs_rsa_cipher.append(cipher_usrs_pub_key[i].encrypt(kc))

	# Convertion de la cle pub en bytes
	read_my_rsa_pub_cipher = open(my_rsa_pub_cipher).read()
	bmy_rsa_pub_cipher = str.encode(read_my_rsa_pub_cipher)

	# Generation du hash -> sha256( cipher_pub_key )
	sha256 = SHA256.new()
	sha256.update(bmy_rsa_pub_cipher)
	myhash = sha256.digest()
   
   	# Creation d'une list de hash des utilisateurs
	usrsHash = []
	for i in range(0,len(usrsRSApub)):
		# Convertion de la cle pub en bytes
		read_usr_rsa_pub_cipher = open(usrsRSApub[i]).read()
		busr_rsa_pub_cipher = str.encode(read_usr_rsa_pub_cipher)

		# generation du hash des USERS -> sha256(cipher_usr_pub_key)
		usrsha256 = SHA256.new()
		usrsha256.update(busr_rsa_pub_cipher)
		usrsHash.append(usrsha256.digest())

	# signature du hash avec cle privee
	signsha256 = SHA256.new()
	signsha256.update(iv)
	signsha256.update(bmsgcipher)
	signature = sign_priv_key.sign(signsha256)

	# DEADBEEF in bytes
	deadbeef = struct.pack('>I', 0xDEADBEEF)
	
	with open(fileout, "wb") as f:
		f.write(myhash)
		f.write(rsa_cipher)
		for i in range(0,len(usrsRSApub)):
			f.write(usrsHash[i])
			f.write(usrs_rsa_cipher[i])
		f.write(deadbeef)
		f.write(iv)
		f.write(bmsgcipher)
		f.write(signature)
		f.close()
	print("Le message a bien été chiffré avec succes :)") 

def decode(filein, fileout,usr_rsa_priv_cipher, usr_rsa_pub_cipher, sender_rsa_pub_sign ):
	with open(filein, "rb") as f:
		data = f.read()

	# Convertion de la cle pub en bytes
	read_usr_rsa_pub_cipher = open(usr_rsa_pub_cipher).read()
	busr_rsa_pub_cipher = str.encode(read_usr_rsa_pub_cipher)

	# Recuperation RSA cipher
	usrsha256 = SHA256.new()
	usrsha256.update(busr_rsa_pub_cipher)
	usrh = usrsha256.digest()

	# Recherche de la position du sha256 du destinataire
	if usrh in data:
		startsha = data.find(usrh)
		endsha = data.find(usrh) + 32
		userHash = data[startsha:endsha]
	
	# Recherche de la position de la cle chiffre du destinataire
	if userHash in data:
		startcipher = data.find(userHash) + 32
		endcipher = startcipher + 256
		userRSAcipher = data[startcipher:endcipher]

	# Recherche de la position DEADBEEF
	deadbeef = struct.pack('>I', 0xDEADBEEF)
	startdeadbeef = data.find(deadbeef)
	enddeadbeef = data.find(deadbeef) + 4
	
	# Recupere IV || C || Sign
	startiv = enddeadbeef
	endiv = startiv + 16
	iv = data[startiv:endiv]

	startc = endiv
	endc = startc + 16
	bmsgcipher = data[startc:endc]

	startsign = endc
	endsign = startsign + 256
	signature = data[startsign:endsign]

	# RSA sign cle pub de l'expediteur
	rsa_sender_pub_sign = RSA.import_key(open(sender_rsa_pub_sign).read())
	sign_sender_pub_key = pss.new(rsa_sender_pub_sign)

	# RSA chiffre cle pub du destinataire
	rsa_usr_priv_key = RSA.importKey(open(usr_rsa_priv_cipher).read())
	cipher_usr_priv_key = PKCS1_OAEP.new(rsa_usr_priv_key)

	# Recuperation de la cle master
	kc = cipher_usr_priv_key.decrypt(userRSAcipher)

	# validation du hash
	sha256 = SHA256.new()
	sha256.update(iv)
	sha256.update(bmsgcipher)

	try:
		sign_sender_pub_key.verify(sha256,signature)
		print("Le message est valide\nVous pouvez dechiffrer le message\n")
	except ValueError:
		print("Le message a été compromis")

	# dechiffrement du message
	try:
		print("Déchiffrement en cours ...")
		cipher = AES.new(kc, AES.MODE_CBC, iv)
		decodemsg = unpad(cipher.decrypt(bmsgcipher), AES.block_size)
		print("Le message secret est : ", decodemsg.decode("utf-8"))
		with open(fileout, "w") as f:
			f.write("Le message secret est : " + decodemsg.decode("utf-8") )
			f.close()

	except ValueError:
		print("Le déchiffrement n'a pas pu aboutir :/")


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

	if sys.argv[1] == "-e":
		print ("\nThis will encrypt\n")
		cipherasym( argv[2], argv[3], argv[4], argv[5], argv[6:] )

	elif sys.argv[1] == "-d":
		print ("\nThis will decrypt\n")
		decode( argv[2], argv[3], argv[4], argv[5], argv[6] )

	else:
		usage()

if __name__ == "__main__":
	main(sys.argv)
