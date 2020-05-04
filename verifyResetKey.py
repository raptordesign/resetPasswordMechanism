from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding



RESET_CIPHER_PUBLIC_KEY_PATH =  "resetCipherPublic.pem"
RESET_CIPHER_PRIVATE_KEY_PATH =  "resetCipherPriv.pem"

RESEY_KEY_PATH = "resetKey.encrypted"

delimiter = '!@#$%^&*()*&^%$#@!'.encode()

def fetchCipherPrivateKey(RESET_CIPHER_PRIVATE_KEY_PATH):
    # read private key file
    with open(RESET_CIPHER_PRIVATE_KEY_PATH, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key
    
def decryptResetKey(RESEY_KEY_PATH, privateKey):
    # read encrypted data file
    with open(RESEY_KEY_PATH, 'rb') as f:
        encrypted = f.read()
    
        
    # Seperate chunks of data
    encryptedChunks = []
    allChunksExtracted = False
    while not allChunksExtracted:
        try:
            index = encrypted.index(delimiter)
            encryptedChunks.append(encrypted[:index])
            encrypted = encrypted[index+len(delimiter):]
        except ValueError:
            allChunksExtracted = True

    # Decrypt each chunk and put them together
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

    print("Data has been decrypted successfully! ")
    
    return original_message

if __name__ == '__main__':
    privateKey = fetchCipherPrivateKey(RESET_CIPHER_PRIVATE_KEY_PATH)

    plainTextResetKey = decryptResetKey(RESEY_KEY_PATH, privateKey)
    
    print("--------------------- Reset Key Content START ---------------------")
    print(plainTextResetKey)
    print("--------------------- Reset Key Content END ---------------------")