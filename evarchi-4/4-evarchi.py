# import libraries
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ECC
from Crypto.Hash import SHAKE128
from Crypto.Signature import eddsa
from Crypto.Protocol.DH import key_agreement
from getpass import getpass
import json
from os.path import isfile

# custom errors
class DSSEncError(Exception):
    '''General error executing DSS Encryption script'''
class ReadProcessingError(DSSEncError):
    '''Error preprocessing data read from file'''
class WriteProcessingError(DSSEncError):
    '''Error writing data in file'''
    
# chiave pubblica della CA
ca_pk = '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAw7LeJPefPraYOphyfgQio1JsjdV1E+kdYxehGslK4Ws=\n-----END PUBLIC KEY-----'


def ECCkey():
    sk = ECC.generate(curve='Ed25519')
    pk = sk.public_key() 
    return sk, pk

def gen_cert():
    sk, pk = ECCkey()

    pas=getPassphrase("Insert a password that is equal or more than 8 character: ") 

    private = sk.export_key(format='PEM', passphrase=pas, protection='scryptAndAES256-GCM', prot_params={'iteration_count':2**20})

    settings = {
    'data': private.encode('utf-8'),
    'subject': 'secret key',
    'error': 'Output aborted.',
    'default': 'sk.pem'
    }
    print('data succesfully written in: '+write_file(**settings))

    cert = {
        'id':'CompitoEvarchi',
        'pubk': pk.export_key(format='PEM'),
        'sig':''
    }
    cert_json=json.dumps(cert)
    settings = {
    'data': cert_json.encode('utf-8'),
    'subject': 'Certificate',
    'error': 'Output aborted.',
    'default': 'Evarchi_cert.cert'
    }
    print('data succesfully written in: '+write_file(**settings))

    print('now you can sign your certificate')

def import_cert(data):
    error_msg = 'Certificate format not valid: '
    try:
        #decode as string and import as json
        cert = json.loads(data)
        #get values to sign
        info = [cert['id'], cert['pubk']]
        if 'sig' in cert:
            info += [b64decode(cert['sig'])]
    except ValueError:
        error_msg += 'encoding error.'
        raise ReadProcessingError(error_msg)
    except TypeError:
        error_msg += 'invalid data.'
        raise ReadProcessingError(error_msg)
    except KeyError as e:
        #certificate does not have 'id' or 'pubk' fields
        error_msg += f'{e} field not found.'
        raise ReadProcessingError(error_msg)
    return info

def getCert():
    while True:
        settings = {
        'subject': 'certificate',
        'error': 'file import aborted.',
        'default': 'Evarchi_cert.cert',
        'process': lambda data: import_cert(data)
        }
        content = read_file(**settings)

        msg=(content[0]+content[1]).encode('utf-8')
        sig = content[2]

        pubKey = importEccKey(ca_pk)

        # Initialise verifying
        verifier = eddsa.new(pubKey, 'rfc8032')
        # Verify
        try:
            verifier.verify(msg, sig)
            return ECC.import_key(content[1])
        except ValueError as e: 
            print("Error during certificate validation, try with another certificate or get it validated by the CA")
            c = input('q to quit, anything else to try again: ')
            if c.lower() == 'q':
                raise ReadProcessingError(e)
    

# This KDF has been agreed in advance
def kdf(x):
    return SHAKE128.new(x).read(32)


def encrypt():
    settings = {
    'subject': 'clear',
    'error': 'file import aborted.',
    'default': '',
    }
    data = read_file(**settings)

    ske, pke=ECCkey()
    pk = getCert()

    DHkey = key_agreement(static_priv=ske, static_pub=pk, kdf=kdf)

    cipher = AES.new(DHkey, AES.MODE_OCB)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    settings = {
    'data': pke.export_key(format='PEM').encode("utf-8")+cipher.nonce+tag+ciphertext,
    'subject': 'cipher',
    'error': 'Output aborted.',
    'default': 'cipher.txt'
    }
    print('data succesfully written in: '+write_file(**settings))


def decrypt():
    settings = {
    'subject': 'encrypted',
    'error': 'file import aborted.',
    'default': 'cipher.txt',
    'process': lambda data: checkLen(data, 143)
    }
    data = read_file(**settings)

    pkee = data[:112]
    nonce = data[112:127]
    tag = data[127:143]
    text = data[143:]

    sk = importEccKey()
    pke = importEccKey(pkee)

    DHkey = key_agreement(static_priv=sk, static_pub=pke, kdf=kdf)

    try:
        cipher = AES.new(DHkey, AES.MODE_OCB, nonce)
        plaintext = cipher.decrypt_and_verify(text,tag)
    except ValueError as e:
        raise ValueError(e)

    settings = {
    'data': plaintext,
    'subject': 'plaintext',
    'error': 'Output aborted.',
    'default': 'plain.txt'
    }
    print('data succesfully written in: '+write_file(**settings))


def importEccKey(k=""):
    while True:
        try:
            if k == "":
                settings = {
                    'subject': 'secret key',
                    'error': 'file import aborted.',
                    'default': 'sk.pem',
                    'process': lambda data: checkLen(data, 273)
                }
                k = read_file(**settings)
                
                pwd=getPassphrase("insert the password to get the key")
                return ECC.import_key(k, pwd)
            else:
                return ECC.import_key(k)
        except ValueError as e:
            print("Error during key validation, retry?")
            k=""
            c = input('q to quit, anything else to try again: ')
            if c.lower() == 'q':
                raise DSSEncError("the key is not correct"+e)


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
                raise WriteProcessingError(error)


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
            return process(data)
        except (IOError, ReadProcessingError) as e:
            print('Error while reading file:\n'+str(e))
            c = input('q to quit, anything else to try again: ')
            if c.lower() == 'q':
                raise ReadProcessingError(error)


# function that checks if the length of the encrypted file is valid
# if not, the program stop and raise an error
# parameters:
# - data: the data we want to check
# - c_len: the minimum length the data needs to have
# return nothing
def checkLen(data, c_len):
    if len(data) < c_len:
        message = 'Error: the data must be at least '
        message += str(c_len) + ' bytes long.'
        raise ReadProcessingError(message)  
    return data
        

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
3 generate certificate
0 quit
→ '''

while True:
    choice = input(prompt)
    try:
        if choice == '1':
            encrypt()
        elif choice == '2':
            decrypt()
        elif choice == '3':
            gen_cert()
        elif choice == '0':
            exit()
        else: 
            print('Invalid choice, try again')
    except DSSEncError as e:
        print(e)