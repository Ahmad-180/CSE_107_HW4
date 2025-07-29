from os import urandom
from Crypto.Cipher.ChaCha20_Poly1305 import new as AE
from hashlib import sha3_256

### Utility methods for authenticated (symmetric) encryption using ChaCha20-Poly1305
# In your solution, you can call these as encrypt2me.auth_encrypt(...) and encrypt2me.auth_decrypt(...)

def auth_encrypt(k, msg):
	nonce = urandom(12)
	ctxt, tag = AE(key=k, nonce=nonce).encrypt_and_digest(msg)
	return nonce + tag + ctxt

def auth_decrypt(k, ctxt):
	if type(ctxt) != bytes or len(ctxt) < 12 + 16:
		raise TypeError("ctxt must be a bytes object of length at least 28")
	try:
		return AE(key=k, nonce=ctxt[:12]).decrypt_and_verify(ctxt[12+16:], ctxt[12:12+16])
	except ValueError:
		print("Decryption failed")
		return None

test_key = urandom(32)
assert auth_decrypt(test_key, auth_encrypt(test_key, b"hello")) == b"hello"
del test_key

### My RSA public key is below

# 2048-bit prime modulus N
N = 0xDC1DD87F48BA7C077A647527A17675B7BC19E701BC1293E9EF748F4A2FF7CF138A7B0035C045E9600DCC67C9FAA9A69FCB93D1F3019AD2EC75E29A3E09896750039D882F6EAF48AC97135CBB36F590A12E121DEBE30AD9B56B5E40DAFE16E93DC7B5C3F3929C4796F4D582A2585A03E12BF806566A269194A886287E0765DE72D143A515A21510EFA53B58C40E8404E1090205F279961921603F68AD023A6D0B4E700D6F0C6DE11ED2F8446C978EB2585B9606E40ABB1EA88D0E708E05C3BB5918DBEBF8F3B855FC5A86D9A8C46C8C21B84315849C4AC5F4480D32417009458630482BA0242332E75AD3ECC30105F6529AD13BAEC4512EA137AA79C0B4BA51AB
# NOTE: I promise you, the number above really is prime

# public exponent e
e = 65537

my_pk = (N, e)

# You can access N and e from hw4.py as encrypt2me.N and encrypt2me.e

### Encryption code

def encrypt(pk, msg):
	(N, e) = pk # in Python this syntax lets you split a tuple into its components. It means the same thing as "N = pk[0]; e = pk[1]"
	x = int.from_bytes(urandom(256), byteorder="big") % N # 256 random bytes = 2048 random bits
	y = pow(x, e, N)
	k = sha3_256(x.to_bytes(256, byteorder="big")).digest()
	ct1 = y.to_bytes(256, byteorder="big") # the first 256 bytes of the ciphertext are ct1
	assert len(ct1) == 256
	ct2 = auth_encrypt(k, msg) # and the rest are ct2
	return ct1 + ct2

# There's no decrypt function here, because the Encrypt2Me library just does encryption (to me). (This is Encrypt2Me, not DecryptFromYou!)

if __name__ == "__main__":
	import sys
	if len(sys.argv) < 2:
		print("Usage: python3 encrypt2me.py message.in [ciphertext.out]")
		print("(if input file is \"-\", reads from stdin)")
		print("(if no output file given, hex-encodes and prints to stdout)")
		exit(1)
	if sys.argv[1] == "-":
		msg = sys.stdin.buffer.read()
	else:
		with open(sys.argv[1],'rb') as f:
			msg = f.read()
	ctxt = encrypt(my_pk, msg)
	if len(sys.argv) == 2:
		print(ctxt.hex())
	else:
		with open(sys.argv[2],'wb') as f:
			f.write(ctxt)