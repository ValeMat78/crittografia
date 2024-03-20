# import of libraries
from Crypto.Random import get_random_bytes
from Crypto.Hash import BLAKE2b
from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import AES
from getpass import getpass
import json
import os.path

# function that with the scrypt method return a secure password
# used scrypt beacuse is secure and fast
# parameters:
# - password: the pasphrase we need to elaborate
# - salt: random numbers
# return the result of the scrypt function
def process_pwd(password, salt):
    return scrypt(password, salt, 16, N=2**20, r=8, p=1)

# function that open the wanted file,
# read the encrypted data and decrypt them with AES mode OCB
# OCB is a standard algorithm that is fast and gives a ful protection  
# parameter:
# - path: the name of the file to read
# - password: the plain password to be elaborated that is needed to decrypt the data
# return the decrypted data as a json
def load_data(path, password):
    with open(path, 'rb') as in_file:

        salt = in_file.read(16)
        nonce = in_file.read(15)
        tag = in_file.read(16)
        content = in_file.read(-1)
    
    pas = process_pwd(password, salt)
    cipher = AES.new(pas, AES.MODE_OCB, nonce)
    data = cipher.decrypt_and_verify(content, tag)

    try: 
        credentials = json.loads(data.decode('utf-8'))
    except ValueError as err:
        raise IOError(f'data not valid: {str(err)}')
    return credentials

# function that encrypt with AES mode OCB the plain data and save it a the file
# parameters:
# - path: the name of the file where to save the data
# - password: the plain password to be elaborated that is used to encypt the data
# - credentials: the data to enrypt
def save_and_exit(path, password, credentials):
    data = json.dumps(credentials, ensure_ascii=False).encode('utf-8')

    salt = get_random_bytes(16)
    pas = process_pwd(password, salt)

    cipher = AES.new(pas, AES.MODE_OCB)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    with open(path, 'wb') as out_file:

        out_file.write(salt)
        out_file.write(cipher.nonce)
        out_file.write(tag)
        out_file.write(ciphertext)

# function that handle the reserch of the credentials and the add for new credentials
# if the wanted credential exist print the credentials
# if do not exist ask we want to save it as a new credential asking the new username and password
# parameters: 
# - query: the id of the credentials we search
# - dic: list of credentials where to search
# return the new list of credentials
def search_and_add(query, dic):
    if query in dic:
        print('username: ', dic[query]['username'])
        print('password: ', dic[query]['password'])
    else:
        prompt = 'Credentials not found. Add new entry?'
        prompt += '\n(y to continue, anything else to cancel)\n'
        add = input(prompt)
        if add == 'y':
            username_n = input('Insert username: ')

            password_n = getpass("insert your password: ")
            dic[query] = {
                    'username': username_n,
                    'password': password_n
                    }
    return dic

# function that derive the file name with the hash function BLAKE2b from the username
# BLAKE2b because is one of finalist for the standard SHA-3 and is fast on modern CPU
# and it work better on 64-bit platform differently from the BLAKE2s
# if the user do not exist, the function ask we want to create a new user/file
# than the it ask at the user what credential to show until the user leave a blank
# than the function recall at the function to save the file
def log_in(username, password):
    h = BLAKE2b.new(data=username.encode(),digest_bits=512)
    path_file = h.hexdigest()
    if os.path.exists(path_file):
        try:
            credentials = load_data(path_file, password)
            print(credentials)
        except ValueError as err:
            print('Autentication failed')
            return
        except IOError as err:
            print('Error loading data:')
            print(err)
            return
    else:
        prompt = 'User not found. Add as new?'
        prompt += '\n(y to continue, anything else to cancel)\n'
        sign_up = input(prompt)
        if sign_up == 'y':
            credentials = {}    
        else:
            return
    prompt = 'Credentials to search:'
    prompt += '\n(leave blank and press "enter" to save and exit)\n'
    while True:
        query = input(prompt)
        if query != '':
            credentials = search_and_add(query, credentials)
        else:
            try:
                print('Saving data...')
                save_and_exit(path_file, password, credentials)
                print('Data saved!')
            except IOError:
                print('Error while saving, new data has not been updated!')
            return

#MAIN
# ask for username and password using the method getpass that do not show the password when you are writing it
while True:
    print('Insert username and password to load data,')
    print('leave blank and press "enter" to exit.')
    username = input('Username: ')
    if username == '':
        print('Goodbye!')
        exit()
    else:
        password = getpass("insert your password: ")
        log_in(username, password)