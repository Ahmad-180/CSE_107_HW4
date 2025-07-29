import encrypt2me
from Crypto.Cipher.ChaCha20_Poly1305 import new as AE
from hashlib import sha3_256
from os import urandom

def list_collaborators():
	# TODO: Edit the string below to list your collaborators. The autograder won't accept your submission until you do.
	return "no collaborators."

def run_attack(ciphertext):
	N, e = encrypt2me.N, encrypt2me.e
	ct1 = ciphertext[:256]
	ct2 = ciphertext[256:]
	y = int.from_bytes(ct1, 'big')
	d = pow(e, -1, N - 1)          
	x = pow(y, d, N)               
	k = sha3_256(x.to_bytes(256, 'big')).digest()
	pt = encrypt2me.auth_decrypt(k, ct2)
	if pt is None:
		raise ValueError("auth_decrypt failed")
	return pt

# ------------------------------------------------------------------------------
# You don't need to (and should not) edit anything below, but feel free to read it if you're curious!
# It's for letting you test your code locally and for interfacing with the autograder

def run_locally():
	print("Testing with an encryption of a randomly generated plaintext...")
	test_plaintext = b"plaintext (random hex digits follow) " + urandom(10).hex().encode('ascii')
	ciphertext = encrypt2me.encrypt(encrypt2me.my_pk, test_plaintext)
	recovered = run_attack(ciphertext)
	if recovered == test_plaintext:
		print("Success!")
	else:
		print("The plaintext you recovered is wrong:")
		print()
		print("ciphertext (hex):", ciphertext.hex())
		print()
		print("correct plaintext:", test_plaintext)
		print("you returned:", recovered)

def interact_with_autograder():
	# Run in 'autograder' mode, where we read the ciphertext from a file,
	# and write the decrypted plaintext to a file
	with open("collaborators", "w") as f:
		f.write(list_collaborators())
	with open("ciphertext", "rb") as f_in:
		ciphertext = f_in.read()
	decrypted = run_attack(ciphertext)
	with open("decrypted","wb") as f_out:
		f_out.write(decrypted)

if __name__ == "__main__":
	from sys import argv
	if len(argv) >= 2 and argv[1] == "--autograder":
		interact_with_autograder()
	else:
		run_locally()