cmd to cipher:
python3 multi_protect.py -e message test my_sign_priv.pem my_ciph_pub.pem usr_ciph_pub.pem usr2_ciph_pub.pem usr3_ciph_pub.pem

cmd to decrypt:
python3 multi_protect.py -d test dechiffre usr2_ciph_priv.pem usr2_ciph_pub.pem my_sign_pub.pem 
