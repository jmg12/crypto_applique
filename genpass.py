import random
import string

def gen_passwd (length , alphabet ):
	res = ""	

	# option 1
	for i in range(length):
		res += random.choice(alphabet)
	# option 2
	res = "".join(random.choice(alphabet) for i in range(length))
	return res

test = gen_passwd(4,"tioa")
print(test)
