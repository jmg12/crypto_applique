import os
import binascii
from struct import pack

from Crypto.Hash import SHA256


def deriv_passwd(password, salt, counter=5000):
    """
    Very easy password derivation function

    - H0 = SHA256(password || salt || 0) # 0 == 0x00000000 (little endian)
    - Hi = SHA256(Hi-1 || password || salt || i) # i is in little endian

    return the value Hn[0:32]
    """
    # compute H0
    sha256 = SHA256.new()
    sha256.update(password)
    sha256.update(salt)
    sha256.update(pack("<I", 0))
    _H0 = sha256.digest()
    #_H0 = SHA256.new(password + salt + pack("<I", 0)).digest()


    _Hi = _H0
    # compute Hi
    for i in range(1, counter):
        sha256 = SHA256.new()
        sha256.update(_Hi)
        sha256.update(password)
        sha256.update(salt)
        sha256.update(pack("<I", i))
        _Hi = sha256.digest()
        #_Hi = SHA256.new(_Hi + password + salt + pack("<I", i)).digest()
    # end for

    return _Hi
# end deriv_passwd


k = deriv_passwd(b'toto', b'00000000', 5000)
print(binascii.hexlify(k))

