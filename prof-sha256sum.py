# sha256sum

import os
from Crypto.Hash import SHA256


def sha256sum(file_path):
    if not os.path.isfile(file_path):
        return None
    # end if

    _chunk_sz = 512
    # init SHA256 ctx
    sha256 = SHA256.new()
    # openfile
    with open(file_path, "rb") as f_in:
        data = f_in.read(_chunk_sz)
        while data#len(data) > 0:
            sha256.update(data)
            data = f_in.read(_chunk_sz)
        # end while
    # end with
    return sha256.digest()
# end sha256sum

