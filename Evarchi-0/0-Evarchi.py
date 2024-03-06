alph = 'abcdefghijklmnopqrstuvwxyz '
wordfile = 'ciphertext.txt'

class SubCipherError(Exception):
    '''Error executing Subtitution chiper script'''

#main function
#in_str: string to modify
#key_1: key
#op: operation to do 1 cript, 0 decript
def substitute(in_str, op):
    key_1 = read_file('key.txt')
    #check legth
    if len(in_str) >= len(key_1):
        err_str = 'message to long for the key'
        raise SubCipherError(err_str)
    
    out_str = ''
    for c in range(len(in_str)):
        index = alph.find(in_str[c])
        index1 = alph.find(key_1[c])

        #control for invalid characters
        if index < 0 or index1 <0:
            err_str = 'message contains invalid characters: '
            err_str += str(in_str[c])
            raise SubCipherError(err_str)
        
        #for encrypt
        if op == 1:
            findex=index+index1
            if findex > 27:
                findex -= 27
        #for dencrypt
        elif op ==0:
            findex=index-index1
            if findex < 0:
                findex += 27
        
        #building of the final string
        out_str += alph[findex]

    return out_str

#read the file that has the name recived
def read_file(keyfile):
    try:
        with open(keyfile, 'r') as in_file:
            read_str = in_file.read()
            in_file.close()
    except IOError as e:
        err_str = 'cannot read file "' + keyfile
        err_str += '": ' + str(e)
        raise SubCipherError(err_str)
    return read_str.strip('\n')

#write che crypted word in the ciphertext file
def write_file(word):
    try:
        with open(wordfile, 'w') as in_file:
            print('the cithertext is:\n' + word)
            in_file.write(word)
            in_file.close()
    except IOError as e:
        err_str = 'cannot read file "' + wordfile
        err_str += '": ' + str(e)
        raise SubCipherError(err_str)

def encrypt():
    pt = input('Type message to encrypt:\n')
    ct = substitute(pt, 1)
    write_file(ct)
    
def decrypt():
    ct = read_file('ciphertext.txt')
    pt = substitute(ct, 0)
    print('the uncithertext is:\n' + pt)

#main
prompt = '''what you want to do? 
1 encrypt
2 decrypt
0 quit
→'''

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
            print('invalid choice, try again')
    except SubCipherError as e:
        print(e)