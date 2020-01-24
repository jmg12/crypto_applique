from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad


def protect_asym(filename_in, filename_out, rsa_pub_cipher_filename, rsa_priv_sign_filename):
    # 0x01. read filename_in
    data = open(filename_in, 'rb').read()

    # 0x02. init RSA cipher context
    ciph_key = RSA.import_key(open(rsa_pub_cipher_filename).read())
    cipher_rsa = PKCS1_OAEP.new(ciph_key)

    # 0x03. init RSA sign context
    sign_key = RSA.import_key(open(rsa_priv_sign_filename).read())
    sign_rsa = pss.new(sign_key)

    # 0x04. generate Kc
    kc = get_random_bytes(32)

    # 0x05. generate IV
    iv = get_random_bytes(16)

    # 0x06. symetric cipher
    cipher_aes = AES.new(kc, AES.MODE_CBC, iv)
    encrypted_data = cipher_aes.encrypt(pad(data))

    # 0x07. Kc wrapping
    wrap = cipher_rsa.encrypt(kc)

    # 0x08. sign(IV || WRAP || C)
    sha256 = SHA256.new()
    sha256.update(iv)
    sha256.update(wrap)
    sha256.update(encrypted_data)
    signature = sign_rsa.sign(sha256)

    # 0x09. write content to filename_out
    f_out = open(filename_out, 'wb')
    f_out.write(iv)
    f_out.write(wrap)
    f_out.write(encrypted_data)
    f_out.write(signature)
    f_out.close()
# end protect_asym