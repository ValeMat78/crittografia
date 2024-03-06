alph = 'abcdefghijklmnopqrstuvwxyz '

class SubCipherError(Exception):
    '''Error executing Subtitution chiper script'''

#main function
#in_str: string to modify
#key_1: reference alphabet
#key_2: permuted alphabet
def substitute(in_str, key_1, key_2):
    #check legth
    if len(key_1) != len(key_2):
        err_str = 'keys of different legth'
        raise SubCipherError(err_str)
    out_str = ''
    for c in in_str:
        index = key_1.find(c)
        if index < 0:
            err_str = 'message contains invalid characters: '
            err_str += c
            raise SubCipherError(err_str)
        out_str += key_2[index]
    return out_str

def read_file(name):
    try:
        with open(name, 'r') as in_file:
            read_str = in_file.read()
    except IOError as e:
        err_str = 'cannot read file "' + name
        err_str += '": ' + str(e)
        raise SubCipherError(err_str)
    return read_str.strip('\n')

def encrypt():
    key = read_file('C:/Users/valer/Desktop/key.txt')
    pt = input('Type message to encrypt:\n')
    ct = substitute(pt, alph, key)
    print('the cithertext is:\n' + ct)

def decrypt():
    key = read_file('C:/Users/valer/Desktop/key.txt')
    ct = input('Type message to dencrypt:\n')
    pt = substitute(ct, key, alph)
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
