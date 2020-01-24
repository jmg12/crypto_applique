from Crypto.Hash import SHA256
import os

def sha256sum( filepath ):

	if not os.path.isfile(filepath):
		return None
	
	_chunk_sz = 512
	hashObj = SHA256.new()
	with open(filepath,"rb") as f:
		buf = f.read(_chunk_sz)
		while buf: #len(data) > 0:
			hashObj.update(buf)
			buf = f.read(_chunk_sz)
	# retourne sha256 du contenu de file en hex
	res = hashObj.hexdigest()
	return res 

test = sha256sum("./test")
print test
