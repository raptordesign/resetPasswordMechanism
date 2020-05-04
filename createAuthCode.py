from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

import time
import random
import json
import string
import os

CHUNK_SIZE = 100
RESET_CIPHER_PUBLIC_KEY_PATH ="resetCipherPublic.pem"
RESET_CIPHER_PRIVATE_KEY_PATH = "resetCipherPriv.pem"
FTC_PUBLIC_KEY_PATH ="ftc_public_key.pem"

AUTH_CODE_FILE_NAME = "authCode.encrypted"
RESET_PASSWORD_AUTH_CODE_PATH = AUTH_CODE_FILE_NAME
CIPHER_VALIDITY_TIME_PERIOD_SECS = 86400
CRYPTOGRAPHIC_NONCE_LENGTH = 128
delimiter = '!@#$%^&*()*&^%$#@!'.encode()

''' ResetPassword Helper Methods Start '''

def generateNonce(stringLength):
    """ Generate a random alphanumberic string of size <stringLength> """
    lettersAndDigits = string.ascii_letters + string.digits
    return ''.join((random.choice(lettersAndDigits) for i in range(stringLength)))

def splitIntoChunks(array, n):
    """ Yield successive n-sized chunks from array."""
    for i in range(0, len(array), n):
        yield array[i:i + n]

CIPHER_PUBLIC_EXPONENT = 65537
CIPHER_KEY_SIZE = 2048

    
def createCipher():
    private_key = rsa.generate_private_key(
        public_exponent=CIPHER_PUBLIC_EXPONENT,
        key_size=CIPHER_KEY_SIZE,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return public_key,private_key

def saveCipherPublicKey(public_key):
    # return public key
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(RESET_CIPHER_PUBLIC_KEY_PATH, 'wb') as f:
        f.write(pem)

def saveCipherPrivateKey(private_key):

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(RESET_CIPHER_PRIVATE_KEY_PATH, 'wb') as f:
        f.write(pem)

def fetchExistingKeys():
    # read public key
    with open(RESET_CIPHER_PUBLIC_KEY_PATH, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    # read private key file
    with open(RESET_CIPHER_PRIVATE_KEY_PATH, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    return public_key, private_key

def encrypt(data, public_key):

    chunks = splitIntoChunks(data.encode(), CHUNK_SIZE)
    encryptedData = bytearray()
    for chunk in chunks:
        # encrypt data
        encryptedChunk = public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encryptedData += encryptedChunk
        encryptedData += delimiter
    return encryptedData

def getPublicKeyBytes(public_key):

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key_bytes.decode()

''' ResetPassword Helper Methods End '''


if __name__ == "__main__":

    
    # New cipher will be created only if this is the first reset passwor request or if 24 hours have passed since it was created else old cipher will be used
    # Check if cipher needs to be created
    if os.path.isfile(RESET_CIPHER_PUBLIC_KEY_PATH):
        if  time.time() - os.path.getmtime(RESET_CIPHER_PUBLIC_KEY_PATH) > CIPHER_VALIDITY_TIME_PERIOD_SECS: 
            print("Existing cipher has expired. Creating new cipher now.")
            isNewCipherRequired = True
        else:
            print("Existing cipher is valid. Using existing cipher to create authCode now.")
            isNewCipherRequired = False
    else:
        print("No existing cipher found. Creating new cipher now.")
        isNewCipherRequired = True

    if isNewCipherRequired:
        public_key, private_key = createCipher()
        saveCipherPrivateKey(private_key)
        saveCipherPublicKey(public_key)
        
        print("New cipher created and saved.")
    else:
        # read existing cipher
        public_key, private_key = fetchExistingKeys()
    
    

    # generate authCode
    authCode = {
        "serialNuber":"",
        "iat":int(time.time()),
        "ext":int(time.time())+CIPHER_VALIDITY_TIME_PERIOD_SECS,
        "cryptographicNonce":generateNonce(stringLength = CRYPTOGRAPHIC_NONCE_LENGTH),
        "cipher":getPublicKeyBytes(public_key)
    }

    # read public key
    with open(FTC_PUBLIC_KEY_PATH, "rb") as key_file:
        ftc_public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    encryptedAuthCode = encrypt(json.dumps(authCode), ftc_public_key)

    # save encrypted authCode to file to facilitate download
    
    with open(RESET_PASSWORD_AUTH_CODE_PATH, 'wb') as f:
        f.write(encryptedAuthCode)

    print("AuthCode has been created! Saved at " + RESET_PASSWORD_AUTH_CODE_PATH)
