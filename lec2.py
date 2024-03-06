
# import cryptography module
from Crypto.Random import get_random_bytes

# custom errors
class SymEncError(Exception):
    '''Error executing Symmetric Encryption script'''
class ValidationError(SymEncError):
    '''invalid input'''

# function that handles file input
# parameters:
# - prompt: message to display when acquiring file path
# - validate: function that validates content read,
#   should raise a ValidationError on invalid inputs
# tries to read valid content until success or user aborts

def read_file(prompt, validate = lambda x : None):
    # repeat until a validated input is read or user aborts
    while True:
        # acquire file path
        path = input(prompt)
        # read input managing IOErrors
        try:
            # read content as bytes
            with open(path, 'rb') as in_file:
                content = in_file.read()
            try:
                # validate contents
                validate(content)
                # validation succesful, return content (end of function)
                return content
            except ValidationError as err:
                # print validation error
                print(err)
        except IOError as err:
            err_str = 'Error: Cannot read file "'
            err_str += path + '": ' + str(err)
            print(err_str)
        # no valid content read: try again or abort
        choice = input('(q to abort, anything else to try again) ')
        if choice == 'q':
            raise SymEncError('Input aborted')

# function that handles file output
# parameters:
# - prompt: message to display when acquiring file path
# - data: bytes to be written in file
# tries to write data until success or user aborts

def write_file(prompt, data):
    # repeat until successful write or user aborts
    while True:
        # acquire file path
        path = input(prompt)
        # write input managing IOErrors
        try:
            # write content as bytes
            with open(path, 'wb') as out_file:
                out_file.write(data)
            return 'Data successfully written in file "' + path + '".'
        except IOError as e:
            print('Error: Cannot write file "' + path + '": ' + str(e))
        # write insuccesful: try again or abort
        choice = input('(q to abort, anything else to try again) ')
        if choice == 'q':
            raise SymEncError('Output aborted')

# function that validates length
# parameters:
# data: byte string to check
# d_len: length in bytes the data must have

def check_len(data, d_len):
    if len(data) != d_len:
        err_msg = 'Error: the data must be exactly '
        err_msg += d_len + ' bytes long, the input was '
        err_msg += len(data) + ' bytes long.'
        raise ValidationError(err_msg)


# read data validating its length
data16 = read_file(
    "Please insert path of a file containing 16 bytes: ",
    lambda data: check_len(data, 16)
)
d1 = data16[:4]
d2 = data16[4:8]
d3 = data16[8:]
data_new = d3 + d2 + d1 + get_random_bytes(16)

print(write_file(
    "Please insert path where to save processed data",
    data_new
))

