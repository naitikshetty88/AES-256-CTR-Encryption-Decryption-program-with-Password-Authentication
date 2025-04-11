import sys #To trigger program exit
import bcrypt # install bcrypt
from Crypto.Cipher import AES # install pycryptodome
from Crypto.Util.Padding import pad, unpad #padding

#genrating key from password
def bcrypt_hash(password):#Hahsing alorithm
   try:
      password = password.encode()#Only accepts paaswords upto 72 bytes long. Also encoded as per UTF-8. Moditications can be made to remove this however passwords greater than 72 bytes can be considered too long and dificult to remember.
      salt = b'$2b$12$HZXPpzTG8jUKr8GZl35K4u'#Additional input added to KDF to protect against rainbow table attacks (precomputed hash values)
      key = bcrypt.kdf(password, salt, desired_key_bytes=32, rounds=300) #Key derivation function using bcrypt. Key lenght = 32 bytes/256 bits for AES-256, Intentional high number of rounds to slow the function and make brute force attacks computationally infeasable.
      return key, salt
   except Exception as e:
        print("No password given")
#Encryption Algorithm function
def encryption(key, plaintext):
    cipher_encrypt = AES.new(key, AES.MODE_CTR)#Initialization for AES256-CTR mode
    ciphertext = cipher_encrypt.encrypt(pad(plaintext,AES.block_size))#encryption using AES-256 CTR. The plaintext is padded to hide its actual length
    return ciphertext, cipher_encrypt.nonce#returns ciphertext and nonce
#Decryption Algorithm function
def decryption(key, nonce, ciphertext):
    try:
       cipher_decrypt = AES.new(key, AES.MODE_CTR, nonce=nonce) #Initialization for AES256-CTR mode
       plaintext = cipher_decrypt.decrypt(ciphertext)#decryption
       plaintext = unpad(plaintext,AES.block_size)#Padding is removed from plaintext
       return plaintext
    except Exception as e:
        print("Incorrect Decryption")#Error handling for incorrect decryption
        print("Do you wish to continue? Press y if yes")#Option to try again
        option2 = input()
        if option2=='y':
            main()
        else:
            sys.exit()
def main():
    try:
       print("Welcome!")
       print("Please Select your option:")
       print("Select 1 for Encryption")
       print("Select 2 for Decryption")
       print("Any other option will close the program")#Selection option 
       option = input()
    
       if option == '1':#For Encryption
           # Input secret password
           Password = input("Enter password: ")
           # Password hashing using bcrypt library
           key, salt = bcrypt_hash(Password)
           # Get secret
           secret = input("Enter your Secret: ")
           secret = secret.encode()
           ciphertext, nonce = encryption(key,secret)#Calling the Encryption function
           ciphertext = ciphertext.hex()#Converts bytes to hexadecimal value to store
           print("Ciphertext: ",ciphertext)
           noncehex = nonce.hex()#Converts bytes to hexadecimal value to store
           print("Nonce: ",noncehex)
           with open("Encrypted_file2.txt","w") as file:#Writes ciphertext to file
               file.write(ciphertext)
           with open("Nonce_file2.txt","w") as file:#Writes Nonce to file
               file.write(noncehex)          
       elif option == '2':#For Decryption
              
            print("Enter the ciphertextfile(including the extension): ")
            ciphertextfile = input()
            with open(ciphertextfile,"r") as file:#Reads ciphertext from chosen file
                ciphertext = file.read()
            ciphertext2 = bytes.fromhex(ciphertext)#Converts hexadecimal value to bytes
            # Input secret password
            Password = input("Enter password: ")
            # Password hashing using bcrypt library
            key, salt = bcrypt_hash(Password)
            cipher_encrypt = AES.new(key, AES.MODE_CTR)
            noncefile = input("Enter the Noncefile(including the extension): ")
            with open(noncefile,"r") as file:#Reads Nonce value from chosen file
                nonce = file.read()
            nonceback = bytes.fromhex(nonce)#Converts hexadecimal value to bytes
            plaintext = decryption(key, nonceback, ciphertext2)
            print("Decrypted message:", plaintext.decode())
            print("Try again? Press y if yes")
            option2 =input()
            if option2 == 'y':
                main()
            else:
                print("Closing the program...")
                sys.exit()
                
       else:
           print("Closing the program...")
           sys.exit()#Exits program
    except Exception as e:#Error Handling
        print("Error")
main()#Starts thye program