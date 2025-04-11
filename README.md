# AES-256-CTR-Encryption-Decryption-program-with-Password-Authentication
The Python script CryptoFinal.py is a comand-line program to encrypt and store secrets or decrypt stored secrets using a Password
## Dependencies - 
- bcrypt: Python library for hashing and key derivation
- pycryptodome: Python library for AES cryptographic primitives

## Features - 
- Passord hashing and key derivation using bcrypt for secure authentication and 256-bit key derivation.
- Encryption of plaintext using AES-256 CTR mode.
- Decryption of ciphertext using AES-256 CTR mode.
- Write/Read of encrypted messages in Encrypted_file1.txt and Nonce1.txt

## Prerequisitues
Install Python
On Windows run command on terminal
 - pip install python
Unix run command on terminal
 - sudo apt-get update
 - sudo apt-get insatll python3

Install the required dependencies
Run command
 - pip insatll bcrypt
 - pip insatll pycryptodome

# How to run python script CryptoFinal.py
 - Download the files CryptoFinal.py, Encrypted_file1.txt, Nonce_file1.txt, Password1.txt, Encrypted_file2.txt, Nonce_file2.txt, README.md
 - Store these files in a sepate repository
 - Open terminal and in the command line go to the repository where these files are stored
 - Run the command : python CryptoFinal.py
 - Follow the instructions mentioned in the command line
For Encryption:
 - Input 1 on the terminal to encrypt a file
 - Enter a password of your choice
 - Enter the secret that needs to be encrypted.
For Decryption
 - Enter the file name (including the extention such as .txt) where the encrypted message is stored
 - Enter the same password used for Encryption
 - Enter the file name (including the extention such as .txt) where the nonce is stored.
After the program is completed user will be asked if they want to continue.
Press 'y' for yes and anything else(prefereably 'n') to exit program.

## File Structure:
 - CryptoFinal.py : Python script to be executed
 - Encrypted_file1.txt : Sample encrypted message whose password is provided in Password1.txt
 - Nonce_file1.txt : Stores Nonce derived from ciphertext present in Encrypted_file1.txt
 - Paasword1.txt : Stores password for the decryption of ciphertext in Encrypted_file1.txt
 - Encrypted_file2.txt : Sample encrypted message.
 - Nonce_file2.txt : Stores Nonce derived from ciphertext present in Encrypted_file2.txt

## Considerations:
 - Ensure all the sensitive files are stored securely
