
# import libraries
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from getpass import getpass

# custom errors
class SymEncError(Exception):
    '''Error executing Symmetric Encryption script'''
class ValidationError(SymEncError):
    '''invalid input'''
class ReadProcessingError(SymEncError):
    '''Error preprocessing data read from file'''


# function that read file as bytes
# parameters:
# - prompt: question on which file we want to read
# if can't open file ask if you want to retry with another file path
def read_file(prompt):
    while True:
        op_file = input(prompt)
        try:
            with open(op_file, 'rb') as in_file:
                content = in_file.read()
                in_file.close()
            return content
        
        except IOError as e:
            err_str = 'Error: Cannot read file "'
            err_str += op_file + '": ' + str(e)

        choice = input("file doesn't exist, do you want to retry? y/n")
        if(choice != 'y'):
           raise ReadProcessingError(err_str)


# function that write file in output as bytes
# parameters:
# - prompt: question for which file we want to write to
# - data: bytes to be written in the file
# if can't write file ask if you want to retry with another file path
def write_file(prompt,data):
    while True:
        path = input(prompt)
        try:
            with open(path, 'wb') as out_file:
                out_file.write(data)
                out_file.close()
                return 'Data successfully written in file "' + path + '".'
            
        except IOError as e:
                err_str = 'Error: Cannot read file "'
                err_str += out_file + '": ' + str(e)

        choice = input('An error occured, do you want to retry? y/n')
        if choice != 'y':
            raise ValidationError(err_str)

# function called to manage the encryption process 
# ask what file we want to encrypt
# ask for the password
# call the function that encrypt the data
# call the function that write the result on a file
def encrypt():
    content = read_file('What file do you want to encrypt? ')
    
    pas=getPassphrase("Insert the password that is equal or more than 8 character: ")
                    
    en_str = ''
    en_str = OCB_en(content,pas)

    print(write_file('On what file you want to write the result? ',en_str))


# function called to manage the decryption process
# ask what file we want to decrypt
# ask for the password
# call the function that decrypt the data
# call the function that write the result on a file
def decrypt():
    content = read_file('What file do you want to decrypt? ')
    checkLen(content,47)
    pas=getPassphrase("insert the password: ")
    en_str = ''
    en_str = OCB_de(content,pas)

    print(write_file('On what file you want to write the result? ',en_str))

# functions that encrypt the data with OCB, 
# create the key with a password and the PBKDF2 function
# call the function to control the length of the encrypted data
# parameters:
# - data: the data we need to encrypt
# - pas: the password to create the key
# return the result of the operation
def OCB_en(data,pas):
    salt = get_random_bytes(16)
    key = scrypt(pas, salt, 16, N=2**20, r=8, p=1)
    cipher = AES.new(key, AES.MODE_OCB)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    data = tag + cipher.nonce + salt + ciphertext
    return data

# functions that decrypt the data, 
# call the function to control the length of the encrypted data
# gets the tag, nonce, salt, ciphertext from the data recived
# recreate the key from the password
# parameters:
# - data: the data we need to decrypt
# - pas: the password to recreate the key
# return the result of the operation
def OCB_de(data,pas):
    tag = data[:16]
    nonce = data[16:31]
    salt = data[31:47]
    ciphertext = data[47:]
    
    key = scrypt(pas, salt, 16, N=2**20, r=8, p=1)
    try:
        cipher = AES.new(key, AES.MODE_OCB, nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext,tag)
        return plaintext
    except ValueError as e:
        raise ValueError(e)

# function that checks if the length of the encrypted file is valid (47 bytes)
# if not, the program stop and raise an error
# parameters:
# - data: the data we want to check
# - c_len: the minimum length the data needs to have
# return nothing
def checkLen(data, c_len):
    if len(data) <= c_len:
        message = 'Error: the ciphertext must be at least '
        message += str(c_len) + ' bytes long.'
        raise ReadProcessingError(message)  
        

#function that ask for the password end check if it is not empty and has more than 8 characters
# the function will ask until we enter a valid 8 or more characters 
# parameters:
# - prompt: the message to show
# return the password as bytes
def getPassphrase(prompt):
    while True:
        pw = getpass(prompt)
        if len(pw) >= 8:
            return pw
        else:
            prompt = "the password is to short:"

# main
# cycle that ask what operation we want until we insert the value 0
# the cycle continue until a valid value is inserted 
prompt = '''What you want to do? 
1 encrypt
2 decrypt
0 quit
→ '''

while True:
    choice = input(prompt)
    try:
        if choice == '1':
            encrypt()
        elif choice == '2':
            decrypt()
        elif choice == '0':
            exit()
        else: 
            print('Invalid choice, try again')
    except ValidationError as e:
        print(e)