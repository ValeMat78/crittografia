alph = 'abcdefghijklmnopqrstuvwxyz '

class MyError(Exception):
    '''custom error'''

a='ciao '
b='a tutti'
#print(a+b)

def function(my_string):
    n = 0
    for c in my_string:
        try:
            i = alph.index(c)
            print(i)
            n += i
        except ValueError as e:
            err_string = 'My error: '+ str(e)
            err_string += ': '+ c
            raise(MyError(err_string))
    return n
        
#leggere e scrivere da file
try:
    with open('C:/Users/valer/Desktop/file.txt', 'r') as input_file:
        text = input_file.read()
except IOError as e:
    err_string = 'Errore while reading: ' + str(e)
    raise MyError(err_string)

try:
    #text = input('write something: ')
    nn = function(text)
    print(nn)
except MyError as e:
    print(e)


'''
for c in alph:
    if c == a[1]:
        print(c)
'''
        
    
