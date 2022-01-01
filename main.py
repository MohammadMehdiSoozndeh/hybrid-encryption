import blowfish
import rsa
import hashlib
from os import urandom

print("A Hybrid Cryptography Algorithm for Cloud Computing Security\n")

data = urandom(8)
print("original data (f) => " + data.hex() + "\n_______\n")

random_key = urandom(56)  # 448 bit
print("random secret key (K) => " + str(random_key.hex()))
blowfish_src = blowfish.Cipher(random_key)
(publicKey, privateKey) = rsa.newkeys(1024)
# print(publicKey)
# print(privateKey)
print("\n___________\n")

print("\n\n __ Encryption Phase")
# Encryption Phase
(publicKey2, privateKey2) = rsa.newkeys(1024)
ciphered_data = blowfish_src.encrypt_block(data)
encrypted_key = rsa.encrypt(random_key, publicKey)
message_digest = hashlib.sha256(ciphered_data)
digital_sign = rsa.sign(message_digest.digest(), privateKey2, 'SHA-256')
print("encrypted data (Ef)              => " + ciphered_data.hex())
print("encrypted key (Ek)               => " + encrypted_key.hex())
print("message digest (Md)              => " + str(message_digest.hexdigest()))
print("digital signature (ds)           => " + str(digital_sign))

print("\n\n-- \t send (Ef, Ek, ds) to destination \t -->")

print("\n\n __ Decryption Phase")
# Decryption Phase
original_secret_key = rsa.decrypt(encrypted_key, privateKey)
blowfish_dst = blowfish.Cipher(original_secret_key)
original_data = blowfish_dst.decrypt_block(ciphered_data)

message_digest_dst = hashlib.sha256(ciphered_data)

print("decrypted secret key (K)         => " + original_secret_key.hex())
print("original data (f)                => " + original_data.hex())
print("message digest (Md)              => " + str(message_digest_dst.hexdigest()))
print("digital signature verification   => " + rsa.verify(message_digest_dst.digest(), digital_sign, publicKey2))
# print("digital signature verification   => " + rsa.verify(b'test-tempered-signature', digital_sign, publicKey2))
