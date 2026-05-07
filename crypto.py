# Encryption and decryption using ECC + AES-GCM (ECIES scheme).


import os
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509


#loads certificate from a .pem file.

def load_cert(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())
    
# loads private EC key from a .pem file.
def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)
    pass

# HKDF 
def _derive_key(shared_secret):
    return HKDF(algorithm=hashes.SHA256(),
                length=32,      #coz we want 32bytes long key (AES-looking key)
                salt=None, 
                info=b"ecies key wrap").derive(shared_secret)


#   plaintext    (str)  — e.g. "Hello everyone!"
#   member_certs (dict) — { "alice": <cert>, "bob": <cert>, ... }

# returns dict:
#   {
#     "ciphertext": "...",        AES-encrypted message (base64)
#     "nonce":      "...",        nonce for message AES-GCM (base64)
#     "keys": {
#       "alice": {
#           "ephemeral_pub": "...",  one-time EC public key (base64)
#           "wrapped_key":  "...",   AES key encrypted for Alice (base64)
#           "wrap_nonce":   "...",   nonce for key wrapping AES-GCM (base64)
#       },
#       "bob": { ... }
#     }
#   }
def encrypt_message(plaintext, member_certs):
    aes_key = os.urandom(32)   # 256-bit key
    nonce = os.urandom(12)     # 96-bit nonce
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)

    #for each member, wrap the AES key using ECDH + HKDF
    encrypted_keys = {}
    for username, cert in member_certs.items():

        recipient_pub = cert.public_key()
        ephemeral_key = ec.generate_private_key(ec.SECP256R1())
        shared_secret = ephemeral_key.exchange(ECDH(), recipient_pub)
        wrap_key = _derive_key(shared_secret)
        wrap_nonce = os.urandom(12)
        wrapped = AESGCM(wrap_key).encrypt(wrap_nonce, aes_key, None)
        ephemeral_pub_bytes = ephemeral_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint)

        encrypted_keys[username] = {
            "ephemeral_pub": base64.b64encode(ephemeral_pub_bytes).decode(),
            "wrapped_key":   base64.b64encode(wrapped).decode(),
            "wrap_nonce":    base64.b64encode(wrap_nonce).decode()
            }

    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce":      base64.b64encode(nonce).decode(),
        "keys":       encrypted_keys
        }

def decrypt_message(encrypted_data, username, private_key):
    if username not in encrypted_data["keys"]: return None

    entry = encrypted_data["keys"][username]

    ephemeral_pub_bytes = base64.b64decode(entry["ephemeral_pub"])
    ephemeral_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ephemeral_pub_bytes)
    
    shared_secret = private_key.exchange(ECDH(), ephemeral_pub)

    wrap_key = _derive_key(shared_secret)

    wrap_nonce  = base64.b64decode(entry["wrap_nonce"])
    wrapped_key = base64.b64decode(entry["wrapped_key"])
    aes_key = AESGCM(wrap_key).decrypt(wrap_nonce, wrapped_key, None)

    nonce      = base64.b64decode(encrypted_data["nonce"])
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])
    return AESGCM(aes_key).decrypt(nonce, ciphertext, None).decode()
