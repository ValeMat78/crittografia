# import libraries
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from getpass import getpass
from Crypto.PublicKey import RSA
from os.path import isfile

# custom errors
class HybEncError(Exception):
    '''Error executing Symmetric Encryption script'''
class ValidationError(HybEncError):
    '''invalid input'''
class ReadProcessingError(HybEncError):
    '''Error preprocessing data read from file'''

# function that create a pair of keys with RSA based on a password and write it in a file
# parameters:
#   - pas: the password to generate the keys
def genRSAkey(pas):
    mykey = RSA.generate(3072)
    private = mykey.export_key(passphrase=pas, pkcs=8, protection='scryptAndAES256-GCM', prot_params={'iteration_count':131072})
    public = mykey.public_key().export_key()
    settings = {
    'data': public+b'\n'+private,
    'subject': 'keys',
    'error': 'Output aborted.',
    'default': 'mykey.pem'
    }
    print('data succesfully written in: ?'+ write_file(**settings))


# function called to manage the encryption process 
# ask what file we want to encrypt
# ask for the password to generate the RSA keys
# call the function that generate the RSA keys
# aks on which file read the public key
# generate a cipher object with PKCS1_OAEP
# with the public RSA key encrypt a randomly generated session key
# encrypt the data with AES end the sessione key
# save in a file
def encrypt():
    settings = {
    'subject': 'clear',
    'error': 'file import aborted.',
    'default': 'clear.txt',
    'process': lambda data: checkLen(data, 0)
    }
    content = read_file(**settings)
    pas=getPassphrase("Insert a password that is equal or more than 8 character: ") 

    genRSAkey(pas)

    settings = {
    'subject': 'public key',
    'error': 'key import aborted.',
    'default': 'mykey.pem',
    'process': lambda data: checkLen(data, 624)
    }
    rawkey= read_file(**settings)
    publickey = RSA.import_key(rawkey[:624],pas)
    session_key = get_random_bytes(16)

    cipher_rsa = PKCS1_OAEP.new(publickey)
    enc_session_key = cipher_rsa.encrypt(session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    data, tag = cipher_aes.encrypt_and_digest(content)

    en_str = enc_session_key+cipher_aes.nonce+tag+data

    settings = {
    'data': en_str,
    'subject': 'cipher',
    'error': 'Output aborted.',
    'default': 'cipher.txt'
    }
    print('data succesfully written in: '+write_file(**settings))


# function called to manage the decryption process
# ask what file we want to decrypt
# ask in which file it need to read the private key
# ask for the password
# from the encrypted file it takes the encrypted ession key,nonce, tag, end the encrypted data
# decrypt the encrypted session key with the private RSA key
# decrypt the data with the AES session key
# call the function that write the result on a file
def decrypt():
    settings = {
    'subject': 'cipher',
    'error': 'file import aborted.',
    'default': 'cipher.txt',
    'process': lambda data: checkLen(data, 416)
    }
    content = read_file(**settings)

    settings = {
    'subject': 'private key',
    'error': 'key import aborted.',
    'default': 'mykey.pem',
    'process': lambda data: checkLen(data, 625)
    }
    rawkey = read_file(**settings)
    pas=getPassphrase("Insert the password: ")

    privatekey = RSA.import_key(rawkey[625:], pas)
    enc_session_key = content[:384]
    nonce = content[384:400]
    tag = content[400:416]
    data = content[416:]

    cipher_rsa = PKCS1_OAEP.new(privatekey)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    en_str = cipher_aes.decrypt_and_verify(data, tag)

    settings = {
    'data': en_str,
    'subject': 'result',
    'error': 'Output aborted.',
    'default': 'result.txt'
    }
    print('data succesfully written in: '+write_file(**settings))


# function that write file in output as bytes
# parameters:
# - data: data to write in the file
# - subject: the subject we are goin to save
# - error:  the type of error we are generating in case of exception
# - default: the default file name if the input is blank
# if the file already exist ask if you want to overwrite
# if can't write file ask if you want to retry with another file path
# the function continue until the writing the data are written or user aborts it
def write_file(data, subject, error, default=''):  
    while True:

        prompt = 'Insert path to file where to save ' + subject
        if default != '':
            prompt += ' (' + default + ')' 
        prompt += ':\n'

        out_filename = input(prompt)
        if out_filename  == '':
            out_filename  = default
        try:
            if isfile(out_filename):
                prompt = 'File exists, overwrite? '
                prompt += '(n to cancel, anything else to continue)\n'
                overwrite = input(prompt)
                if overwrite.lower() == 'n':
                    continue

            with open(out_filename, 'wb') as out_file:
                out_file.write(data)
            return out_filename
        
        except IOError as e:
            print('Error while saving '+subject+': '+str(e))
            c = input('q to quit, anything else to try again: ')
            if c.lower() == 'q':
                # abort
                raise HybEncError(error)


# function that read file as bytes
# parameters:
# - subject: the information we are going to read
# - error: the type of error we show in case of exceptions
# - default: the file name in case the input is blank
# - process: the proces we are going to do on the readed data
# if can't open file ask if you want to retry with another file path
# the function continue until the data is succesfully readed of user aborts
def read_file(subject, error, default='', process=lambda data: data):
    prompt = 'Insert path to ' + subject + ' file'
    if default != '':
        prompt += ' (' + default + ')' 
    prompt += ':\n'

    while True:
        in_filename = input(prompt)
        if in_filename  == '':
            in_filename  = default

        try:
            with open(in_filename, 'rb') as in_file:
                data = in_file.read()
                process(data)
            return data
        except (IOError, ReadProcessingError) as e:
            print('Error while reading file:\n'+str(e))
            c = input('q to quit, anything else to try again: ')
            if c.lower() == 'q':
                raise HybEncError(error)


# function that checks if the length of the encrypted file is valid
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
# the function will ask until we enter a valid 8 or more characters passphrase
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