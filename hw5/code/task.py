from urllib import request, error
from time import sleep

# Example iv and ciphertext with known plaintext
iv = 'abcdef1234567890abcdef1234567890'
ciphertext = '5ea5810e09cdeaee3d11c24dfd082d2bfd26349c5b75ecec82583cece3d11372f5db1b9420a9cbf228a98ba2d6b7bcbb86f070de15b1145d112b84e62d883d574e17e5f7ad480dbcebbf376cbf85bc27185091120f30fb6ee54623edb96594fc'


# The method probes the web application with a modified ciphertext
# It returns True if padding is correct and False otherwise
# The first param must be a hex string
# The second param must be a hex string


def probe(iv, ciphertext):
    url = 'http://172.26.5.113/index.py?iv=' + iv + '&ciphertext=' + ciphertext
    try:
        response = request.urlopen(url)
        return True
    except error.HTTPError:
        return False


if probe(iv, ciphertext):
    print('Padding is correct')
else:
    print('Something went wrong')

print(bytes.fromhex(ciphertext))
