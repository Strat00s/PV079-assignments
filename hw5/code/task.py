from urllib import request, error
from time import sleep


BLOCK_SIZE = 16

#iv         = 'abcdef1234567890abcdef1234567890'
#ciphertext = '5ea5810e09cdeaee3d11c24dfd082d2bfd26349c5b75ecec82583cece3d11372f5db1b9420a9cbf228a98ba2d6b7bcbb86f070de15b1145d112b84e62d883d574e17e5f7ad480dbcebbf376cbf85bc27185091120f30fb6ee54623edb96594fc'
#plaintext  = "Modern cryptography is heavily based on mathematical theory and computer science practice"

#iv         = '4e17e5f7ad480dbcebbf376cbf85bc27'
#ciphertext = '185091120f30fb6ee54623edb96594fc'


#iv = "f6bc91b8beba35c4b0f1b46a8628e5b4"
#ciphertext = "f6c4d8e9576ba1ea3df5ae9c191591051b11b9766a219f75bf8cefcffb7e67b35057e343feb200110e3c9c3f68ff1438c058c911ab0f2d53f2df782876777fe1e6fec92571eb5fb31c336d85b62846e3"

#iv = "5057e343feb200110e3c9c3f68ff1438"
#ciphertext = "c058c911ab0f2d53f2df782876777fe1"

iv = "c058c911ab0f2d53f2df782876777fe1"
ciphertext = "e6fec92571eb5fb31c336d85b62846e3"

#tanding8888888

# The method probes the web application with a modified ciphertext
# It returns True if padding is correct and False otherwise
# The first param must be a hex string
# The second param must be a hex string


def arrayXor(array_a, array_b):
    return bytearray([a ^ b for a, b in zip(array_a, array_b)])

def generatePairs(array, split_len):
    print(len(array))
    print(len(array) / split_len)
    result = list()
    for i in range(0, len(array) // split_len - 1):
        result.append([array[i * split_len : (i + 1) * split_len], array[(i + 1) * split_len : (i + 2) * split_len]])
    return result

def probe(iv, ciphertext):
    url = 'http://172.26.5.113/index.py?iv=' + iv + '&ciphertext=' + ciphertext
    try:
        response = request.urlopen(url)
        return True
    except error.HTTPError:
        return False


plaintext = ""
iv_ct_pairs = generatePairs(bytearray.fromhex(iv + ciphertext), BLOCK_SIZE)
for iv, ct in iv_ct_pairs:
    msg = bytearray.fromhex("00" * BLOCK_SIZE)
    blocktext = ""
    pad_value = -1
    for i in reversed(range(0, BLOCK_SIZE)):
        padding = bytearray.fromhex("00" * (i + 1)  + f"{BLOCK_SIZE - i:02x}" * (BLOCK_SIZE - i - 1))
        print(f"Padding: {padding.hex()}")
        print(f"Message: {msg.hex()}")
        print(f"IV:      {iv.hex()}")
        print(pad_value)
        old = iv
        for c in range(0, 256):
            #padding skip
            if c ^ (BLOCK_SIZE - i) == BLOCK_SIZE - i and c ^ (BLOCK_SIZE - i) != pad_value:
                continue
            msg[i] = c
            iv = arrayXor (iv, padding)
            iv = arrayXor (iv, msg)
            c = c ^ (BLOCK_SIZE - i)
            if probe(iv.hex(), ct.hex()):
                msg[i] = c
                blocktext = chr(c) + blocktext
                print(f"  {c:02x} ({chr(c) if chr(c).isprintable() else ' '}) {iv.hex()}  |  {plaintext}{blocktext}")
                iv = old
                #padding was found
                if c >= 1 and c <= 16:
                    pad_value = c
                break
            else:
                print(f"  {c:02x} ({chr(c) if chr(c).isprintable() else ' '}) {iv.hex()}  |  {plaintext}{blocktext}", end="\r")
                iv = old
        else:
            print("\nSomething went wrong")
            exit()
    plaintext += blocktext
print(f"Final plaintext: {plaintext}")























#print(ciphertext)
#block_cnt = len(ciphertext) // 16
#print(block_cnt)
#
#
#blocks = splitArray(ciphertext, BLOCK_SIZE)
#
#a = blocks[-2]
#b = blocks[-1]
#
#print(a.hex())
#print(b.hex())
#
#print(a.hex())
#
#plain_block = bytearray.fromhex("00" * BLOCK_SIZE)
#for i in range(0, BLOCK_SIZE):
#    padding     = bytearray.fromhex("00" * BLOCK_SIZE)
#    old_a = a.copy()
#    for c in range(0, 255):
#        sleep(0.25)
#        plain_block[-(i + 1)] = c
#        for j in range(0, i + 1):
#            padding[-(j + 1)] = padding[-(j + 1)] ^ (i + 1)
#        a = arrayXor(a, padding)
#        a = arrayXor(a, plain_block)
#
#        new_ct = blocks[0] + blocks[1] + blocks[2] + blocks[3] + a + b
#        
#        print(f"Plain block: {plain_block.hex()}")
#        print(f"Padding:     {padding.hex()}")
#        print(f"A:           {a.hex()}")
#        if probe(iv.hex(), ciphertext.hex()):
#            print(f"{c} - match")
#            break
#        else:
#            print(f"{c} - bad padding")
#    a = old_a
#
#print(plain_block)
#ciphertext[78] = 0xf9


#ciphertext = bytearray.fromhex(ciphertext)
#for c in reversed(range(0, 256)):
#    old = ciphertext[79]
#    ciphertext[79] = ciphertext[79] ^ c
#    if probe(iv, ciphertext.hex()):
#        print(f"{c}")
#        break
#    ciphertext[79] = old