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


#def cipherasym(filein, fileout, my_rsa_priv_sign, my_rsa_pub_cipher, *buffers):
def cipherasym(filein, fileout, my_rsa_priv_sign, my_rsa_pub_cipher, usr_rsa_pub_cipher):
	data = ""
	with open(filein, "rb") as f:
		data = f.read()

	# DEADBEEF in bytes
	#c = struct.pack('>I', 0xDEADBEEF)
	# TODOO
	#res = struct.unpack('>I',c)
	#hex(res)

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
	usr_rsa_cipher = cipher_usr_pub_key.encrypt(kc)

	# Convertion de la cle pub en bytes
	read_my_rsa_pub_cipher = open(my_rsa_pub_cipher).read()
	bmy_rsa_pub_cipher = str.encode(read_my_rsa_pub_cipher)

	# Generation du hash -> sign( cipher_pub_key )
	sha256 = SHA256.new()
	sha256.update(bmy_rsa_pub_cipher)
	myhash = sha256.digest()
    
	# Convertion de la cle pub en bytes
	read_usr_rsa_pub_cipher = open(usr_rsa_pub_cipher).read()
	busr_rsa_pub_cipher = str.encode(read_usr_rsa_pub_cipher)

	# generation du hash des USERS -> sign(cipher_usr_pub_key)
	usrsha256 = SHA256.new()
	usrsha256.update(busr_rsa_pub_cipher)
	usrh = usrsha256.digest()

	# signature du hash avec cle privee
	signsha256 = SHA256.new()
	signsha256.update(iv)
	signsha256.update(rsa_cipher)
	signsha256.update(bmsgcipher)
    
	signature = sign_priv_key.sign(signsha256)

	print("Hash sender: ", len(myhash))
	print("RSA cipher sender: ", len(rsa_cipher))
	print("hash dest: ", len(usrh))
	print("RSA cipher dest: ", len(usr_rsa_cipher))
	print("IV: ", len(iv))
	print("bmsgcipher: ", len(bmsgcipher))
	print("Signature: ", len(signature))

	with open(fileout, "wb") as f:
		f.write(myhash)
		f.write(rsa_cipher)
		f.write(usrh)
		f.write(usr_rsa_cipher)
		#f.write(b'0xDE0xAD0xBE0xEF')
		f.write(iv)
		f.write(bmsgcipher)
		f.write(signature)
		f.close()

def decode(filename, usr_rsa_priv_cipher, usr_rsa_pub_cipher, sender_rsa_pub_sign ):
	with open(filename, "rb") as f:
		data = f.read()

	# RSA sign cle pub de l'expediteur
	rsa_sender_pub_sign = RSA.import_key(open(sender_rsa_pub_sign).read())
	sign_sender_pub_key = pss.new(rsa_sender_pub_sign)

	# RSA chiffre cle pub du destinataire
	rsa_usr_priv_key = RSA.importKey(open(usr_rsa_priv_cipher).read())
	cipher_usr_priv_key = PKCS1_OAEP.new(rsa_usr_priv_key)

	# Parsing SHA256(kpub-1) || RSA_kpub-1(Kc) || ... || SHA256(kpub-N) || RSA_kpub-N(Kc) || 0xDEADBEEF || IV || C || Sign
	senderHash = data[0:32]
	senderRSAcipher = data[32:288]
	userHash = data[288:320]
	userRSAcipher = data[320:576]
	iv = data[576:592]
	bmsgcipher = data[592:608]
	signature = data[608:864]
	
	#print("Sender hash: ", binascii.hexlify(senderHash), "\n" )
	#print("Sender RSA cipher: ", binascii.hexlify(senderRSAcipher), "\n" )
	#print("User Hash ", binascii.hexlify(userHash), "\n" )
	#print("Sender RSA cipher: ", binascii.hexlify(userRSAcipher), "\n" )
	#print("IV: ", binascii.hexlify(iv), "\n" )
	#print("bmshcipher: ", binascii.hexlify(bmsgcipher), "\n" )
	#print("signature: ", binascii.hexlify(signature), "\n" )

	# Recuperation de la cle master
	kc = cipher_usr_priv_key.decrypt(userRSAcipher)

	# validation du hash
	sha256 = SHA256.new()
	sha256.update(iv)
	sha256.update(senderRSAcipher)
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
	#if len(sys.argv) < 6:
	if len(sys.argv) < 2:
		usage()

#	try:
	if sys.argv[1] == "-e":
		print ("This will encrypt")
		buff = []
		#for arg in argv[6:]:
			#buff.append(arg)
		#print buff
		#cipherasym( argv[2], argv[3], argv[4], argv[5], buff )
		#cipherasym( argv[2], argv[3], argv[4], argv[5], argv[6] )
		cipherasym( "./message", "./test", "my_sign_priv.pem", "my_ciph_pub.pem", "usr_ciph_pub.pem")

	elif sys.argv[1] == "-d":
		print ("This will decrypt")
		decode( "./test", "usr_ciph_priv.pem", "usr_ciph_pub.pem", "my_sign_pub.pem")

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
