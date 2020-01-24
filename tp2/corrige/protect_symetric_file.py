import sys
import os

from Crypto.Random import get_random_bytes

from protect_file.simple_symetric import encrypt_buffer_aes_cbc, compute_hmac_sha256
from password.derivation import deriv_master_key, deriv_passwd


def compute_hmac_sha256(key, *buffers):
    _hmac = HMAC.new(key, digestmod=SHA256)
    for b in buffers:
        _hmac.update(b)
    # end for
    return _hmac.digest()
# end compute_hmac_sha256


def verify_hmac_sha256(key, hmac_value, *buffers):
    _hmac = compute_hmac_sha256(key, *buffers)
    return _hmac == hmac_value
# end verify_hmac_sha256


def main(argv):
    # 00. check arguments
    if len(argv) != 4:
        print("usage: {0} <password> <input_file> <output_file>".format(argv[0]))
        sys.exit(1)
    # end if
    _password = argv[1]
    _input_file_path = argv[2]
    _output_file_path = argv[3]


    # 01. read input file
    _plain_data = ""
    if os.path.exists(_input_file_path):
        _sz = os.path.getsize(_input_file_path)
        if _sz == 0:
            print("error: file is empty")
            sys.exit(1)
        # end if
        with open(_input_file_path, "rb") as f_in:
            _plain_data = f_in.read()
        # end with
    # end if


    # 02. derive password -> km
    _salt = get_random_bytes(8)
    _km = deriv_passwd(_password, _salt, 6000)


    # 03. derive km -> kc & ki
    _kc, _ki = deriv_master_key(_km)


    # 04. encrypt data
    _iv = get_random_bytes(16)
    _encrypted_data = encrypt_buffer_aes_cbc(_kc, _iv, plain_data)


    # 05. compute HMAC
    _hmac = compute_hmac_sha256(_ki, _iv, _salt, _encrypted_data)


    # 06. write encrypted data
    with open(_output_file_path, "wb") as f_out:
        f_out.write(_iv)
        f_out.write(_salt)
        f_out.write(_encrypted_data)
        f_out.write(_hmac)
    # end with

    print("protection done !")
# end main


if __name__ == "__main__":
    main(sys.argv)
# end if
