import base64
import re
import string
from random import *

# extract all potential base64 strings
# decode correct one and store potentials
def scrap_b64str (content):
    # search for base64 strings, shorter than 17 chars is refused
    regexp_b64 = re.compile ('[A-Za-z0-9+/=]{16,}=*')
    words = regexp_b64.findall (content)

    # validate each base64
    # if validated it is added to our list
    results = list()
    for word in words:
        # detect proper base64 string
        found = True
        decoded = ''
        try:
            decoded = base64.b64decode (word)
        except Exception:
            found = False

        # detect potential base64 string (maybe broken base64?)
        if found == False and len (re.findall ('=+$', word)) != 0:
            decoded = word
            found = True

        # store potential base64 string and properly decoded base64 strings
        if found == True and len (decoded) != 0:
            results.append (decoded)
    # return all base64 strings
    return results

def rand_str (length):
    charset = string.letters + string.digits
    return ''.join(choice(charset) for idx in range(length))

