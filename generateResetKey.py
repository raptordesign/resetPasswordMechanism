from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import json

# INPUTS
FTC_PRIVATE_KEY_PATH = "ftc_private_key.pem"
AUTH_CODE_PATH = "authCode.encrypted"

# OUTPUT
RESET_KEY_PATH = "resetKey.encrypted"


CHUNK_SIZE = 100
RESET_CIPHER_PUBLIC_KEY_PATH =  "resetCipherPublic.pem"
RESET_CIPHER_PRIVATE_KEY_PATH = "resetCipherPriv.pem"
FTC_PUBLIC_KEY_PATH = "ftc_public_key.pem"
AUTH_CODE_FILE_NAME = "authCode.encrypted"
RESET_PASSWORD_AUTH_CODE_PATH =  AUTH_CODE_FILE_NAME
CIPHER_VALIDITY_TIME_PERIOD_SECS = 86400
CRYPTOGRAPHIC_NONCE_LENGTH = 128
delimiter = '!@#$%^&*()*&^%$#@!'.encode()

def splitIntoChunks(array, n):
    """ Yield successive n-sized chunks from array."""
    for i in range(0, len(array), n):
        yield array[i:i + n]

def fetchPrivateKey():
    # read private key file
    with open(FTC_PRIVATE_KEY_PATH, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key
    

def decryptAuthCode(AUTH_CODE_PATH, privateKey):
    # read encrypted data file
    with open(AUTH_CODE_PATH, 'rb') as f:
        encrypted = f.read()
        f.close()



    # Retreive chunks of data
    encryptedChunks = []

    allChunksExtracted = False
    while not allChunksExtracted:
        try:
            index = encrypted.index(delimiter)
            encryptedChunks.append(encrypted[:index])
            encrypted = encrypted[index+len(delimiter):]
        except ValueError:
            allChunksExtracted = True

    # decrypt each chunk and append them

    original_message = ""
    for chunk in encryptedChunks:
        original_message += privateKey.decrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()
    
    print("AuthCode has been decrypted successfully!\n ")
    return original_message

def createResetKey(plainTextAuthCode):
    print("\ncreating reset key ...")

    authCodeJson = json.loads(plainTextAuthCode)
    cipher = authCodeJson.pop("cipher")
    key = serialization.load_pem_public_key(
        cipher.encode(),
        backend=default_backend()
    )

    # encrpy data
    f = open(RESET_KEY_PATH, 'wb')
    for chunk in splitIntoChunks(json.dumps(authCodeJson).encode(), CHUNK_SIZE):
        encrypted = key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        f.write(encrypted)
        # delimiter of 50 spaces
        f.write(delimiter)
    f.close()

    print("Reset key has been created! Saved to " + RESET_KEY_PATH)


if __name__ == "__main__":

    privateKey = fetchPrivateKey()

    plainTextAuthCode = decryptAuthCode(AUTH_CODE_PATH, privateKey)

    print("--------------------- AuthCode Content START ---------------------")
    print(plainTextAuthCode)
    print("--------------------- AuthCode Content END ---------------------")

    createResetKey(plainTextAuthCode)
