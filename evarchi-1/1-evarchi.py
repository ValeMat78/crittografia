
# import cryptography libraries
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Cipher import ChaCha20

# custom errors
class SymEncError(Exception):
    '''Error executing Symmetric Encryption script'''
class ValidationError(SymEncError):
    '''invalid input'''
class DecryptionError(ValueError, KeyError):
    '''Decryption failed'''


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

        choice = input("file dosen't exit, do you want to retry? y/n")
        if(choice != 'y'):
           raise ValidationError(err_str)


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

        choice = input('An error accured, do you want to retry? y/n')
        if choice != 'y':
            raise ValidationError(err_str)

# function called to manage the ecryption process
def encrypt():
    content = read_file('What file do you want to encrypt? ')
    # generating a key value of 32 bytes
    key = get_random_bytes(32)
                
    en_str = ''
    # cycle that ask what kind of encryption we want
    # if the value is not valid the cycle continue until a valid value is inserted
    while True:
        op = input('''what kind of ecrypt do you want?
                    1 - with validation
                    2 - without validation
                    → ''')
        
        if(op == '1'):
            en_str = OCB_en(content,key)
            break

        elif(op == '2'):
            en_str = chacha_en(content,key)
            break
        else:
            print('invalid number')

    print(write_file('On what file you want to write the result? ',en_str))


#function called to manage the decryption process
def decrypt():
    content = read_file('What file do you want to decrypt? ')
    key = read_file('From what file you want to read the key? ')

    # cycle that ask what kind of decryption we want
    # if the value is not valid the cycle continue until a valid value is inserted
    while True:
        op = input('''what kind of decrypt do you want?
                    1 - with validation
                    2 - without validation
                    → ''')
        en_str = ''
        if(op == '1'):
            en_str = OCB_de(content,key)
            break

        elif(op == '2'):
            en_str = chacha_de(content,key)
            break
        else:
            print('invalid number')

    print(write_file('On what file you want to write the result? ',en_str))

# functions to encrypt/decrypt without validation made with chacha20 system
def chacha_en(data,key):
    cipher = ChaCha20.new(key=key)
    ciphertext = cipher.encrypt(data)
    print(write_file('On what file you want to write the key? ',key + b'/n' + cipher.nonce))
    return ciphertext
    
def chacha_de(data,key):
    value = key.split(b'/n')
    key = value[0]
    nonce = value[1]
    try:
        cipher = ChaCha20.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt(data)
        return plaintext
    except DecryptionError as e:
        print(e)

# functions to encrypt/decrypt with validation made with OCB system
def OCB_en(data,key):
    cipher = AES.new(key, AES.MODE_OCB)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    print(write_file('On what file you want to write the key? ',key + b'/n' + tag + b'/n' + cipher.nonce))
    return  ciphertext

def OCB_de(data,key):
    value = key.split(b'/n')
    key = value[0]
    tag = value[1]
    nonce = value[2]
    try:
        cipher = AES.new(key, AES.MODE_OCB, nonce)
        plaintext = cipher.decrypt_and_verify(data,tag)
        return plaintext
    except DecryptionError as e:
        print(e)


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