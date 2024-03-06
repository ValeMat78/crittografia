import json


# Opening JSON file
f = open('Evarchi_cert.cert')
 
# returns JSON object as 
# a dictionary
data = json.load(f)
 
print(data['id'])


# Python program to read
# json file
 
import json
 

# Iterating through the json
# list
# for i in data['emp_details']:
#     print(i)
 
# Closing file
# f.close()