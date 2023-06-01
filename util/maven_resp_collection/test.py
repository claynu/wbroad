import base64
import binascii

from cryptography.hazmat.primitives import serialization
from gmssl import sm2, func
import base64
#16进制的公钥和私钥
private_key = 'D5F2AFA24E6BA9071B54A8C9AD735F9A1DE9C4657FA386C09B592694BC118B38'
from cryptography.hazmat.primitives.asymmetric import ec
private_key = ec.generate_private_key(ec.SECP256R1(), None)
public_key = private_key.public_key()
rsa_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
print(rsa_pem)
public_key = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'
sm2_crypt = sm2.CryptSM2(
    public_key=public_key, private_key=private_key)
# 对接java 时验签失败可以使用
sm2_crypt = sm2.CryptSM2(
    public_key=public_key, private_key=private_key)
s = sm2_crypt.encrypt(b'sad')
print(base64.b64encode(s))