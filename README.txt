
##### PRE - REQUISITE #####

Install the crypto python library using 

"python3 -m pip install -r requirements.txt"


Refer to the design diagram to get an overview of how the Reset Password Mechanism works.



------- Auth Code ------

SCENARIO: When the user forgets his password, he will download an authCode from the UI

Run "python3 createAuthCode.py" to create an authCode. This will be saved into the currrent folder.



------- Generate Reset Key from Auth Code ------

SCENARIO: Upon receiving the authCode, FTC will process it and generate the resetKey

Ensure the authCode.encrypted is in the current folder. Run "python3 generateResetKey.py" to process authCode.encrypted and create a resetKey.



------- Verify Reset Key -------

SCENARIO: FTC gives the user the resetKey. Now, the user uploads the resetKey in the ZC WebApp. The ZC verifies the resetKey and allows the user to reset his password.

Ensure the resetKey.encrypted is in the current folder. Run "python3 verifyResetKey.py" to verify the resetKey. 





*********** Supporting Files ************

The ftc_public_key.pem will be distributed on to all the ZCs during software installation.

FTC must keep the ftc_private_key.pem file highly secure. This file will be used to create the resetKey.

The resetCipherPriv.pem and resetCipherPublic.pem files will be created on the ZC during the resetPassword process. 

