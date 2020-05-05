**Functionality**
Refer to the Sequence Diagram to get an overview of the Reset Password functionality.

**Prerequisites**
Prerequisites to run the scripts:
  Install the crypto python library using 
    "python3 -m pip install -r requirements.txt"
    
**Component Diagram**

Zone Controller        
1. createAuthCode.py 
2.  ftc_public_key.pem

FTC
1. generateResetKey.py
2. ftc_private_key.pem
 
**Reset Password steps:**
User forgets password.
User Clicks on Forgot Password.
Application ask the user: "Do you have the Reset Key?"
User selects "No".
Application generates an "Auth Key" and downloads the key.

  - To FTC : Generating Auth Key can be done by running the following command.
   python3 createAuthCode.py 
   
Application asks user to share the Auth Key with the Admin.
User shares Auth Key with the Admin and requests for a Reset Key. 
Admin sends the Auth Key to FTC.
FTC verifies the Auth Key and generates Reset Key.

   - To FTC : Verifying Auth Key and generating Reset Key can be done by running the following command:
    python3 generateResetKey.py 
    
FTC shares the Reset Key with the Admin.
Admin shares the Reset Key with the User.
User clicks on Forgot Password link again.
Application ask the user: "Do you have the Reset Key?"
This time, the User selects "Yes".
Application asks the User to upload the Reset Key.
User uploads the Reset Key.
Application verfies the Reset Key and allows User to Reset the password.

   - To FTC : Verifying Reset Key and authorizing the User to change password can be done by running the following command.
    python3 verifyResetKey.py 



*********** Supporting Files ************

The ftc_public_key.pem will be distributed on to all the ZCs during software installation.

FTC must keep the ftc_private_key.pem file highly secure. This file will be used to create the resetKey.

The resetCipherPriv.pem and resetCipherPublic.pem files will be created on the ZC during the resetPassword process. 

![alt text](https://github.com/AstralPresence/resetPasswordMechanism/blob/master/ForgotPassword.jpg?raw=true)
