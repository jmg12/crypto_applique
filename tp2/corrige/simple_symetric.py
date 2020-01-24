from __future__ import print_function

from Crypto.Hash import SHA256, HMAC
from Crypto.Util.Padding import pad, unpad

#BS = AES.block_size
#pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
#unpad = lambda s: s[0:-ord(s[-1])]


def encrypt_buffer_aes_cbc(key, iv, buffer_in):
    """
    Description
        Encrypt buffer_in with AES-128-CBC algorithm
    Params
        key :
        buffer_in :
    return
        encrypted buffer
    """
    # let's encrypt padded buffer
    _cipher = AES.new(key, AES.MODE_CBC, iv)
    _enc_buffer = _cipher.encrypt(pad(buffer_in, AES.block_size))

    return _enc_buffer
# end encrypt_buffer_aes_cbc


def decrypt_buffer_aes_cbc(key, iv, buffer_in):
    # decrypt
    _decipher = AES.new(key, AES.MODE_CBC, iv)
    _dec_buffer =_decipher.decrypt(buffer_in)

    # remove padding
    return unpad(_dec_buffer, AES.block_size)
# end decrypt_buffer_aes_cbc


def compute_hmac_sha256(key, *buffers):
    _hmac = HMAC.new(key, digestmod=SHA256.new())
    for b in buffers:
        _hmac.update(b)
    # end for
    return _hmac.digest()
# end compute_hmac_sha256


def verify_hmac_sha256(key, hmac_value, *buffers):
    _hmac = compute_hmac_sha256(key, *buffers)
    return _hmac == hmac_value
# end verify_hmac_sha256
