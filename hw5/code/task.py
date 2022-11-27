from urllib import request, error


BLOCK_SIZE = 16


iv = "cad9e05ad4bd01c5bec2ed6d480d5051"
ciphertext = "5fcfe3189957b9c23f8a95e65a51ab74"


def arrayXor(array_a, array_b):
    return bytearray([a ^ b for a, b in zip(array_a, array_b)])

#generate array pairs which are used for attack
def generatePairs(array, split_len):
    print(len(array))
    print(len(array) / split_len)
    result = list()
    for i in range(0, len(array) // split_len - 1):
        result.append([array[i * split_len : (i + 1) * split_len], array[(i + 1) * split_len : (i + 2) * split_len]])
    return result

#same as example
def probe(iv, ciphertext):
    url = 'http://172.26.5.113/index.py?iv=' + iv + '&ciphertext=' + ciphertext
    try:
        response = request.urlopen(url)
        return True
    except error.HTTPError:
        return False

def printable(c):
    return chr(c) if chr(c).isprintable() else ' '


plaintext = ""
iv_ct_pairs = generatePairs(bytearray.fromhex(iv + ciphertext), BLOCK_SIZE)
for iv, ct in iv_ct_pairs:
    msg       = bytearray.fromhex("00" * BLOCK_SIZE)    #current block plaintext "array"
    blocktext = ""                                      #current block plaintext
    pad_value = -1                                      #actuall padding retrieved from plaintext

    for i in reversed(range(0, BLOCK_SIZE)):
        padding = bytearray.fromhex("00" * (i + 1)  + f"{BLOCK_SIZE - i:02x}" * (BLOCK_SIZE - i - 1))   #desired padding "array"
        print(f"Padding: {padding.hex()}")
        print(f"Message: {msg.hex()}")
        old_iv = iv     #save iv for restoring in every round
        for c in range(0, 256):
            c = c ^ (BLOCK_SIZE - i)    #xor immediataly as plain c is used a lot

            #padding skip
            if c == BLOCK_SIZE - i and c != pad_value:
                continue

            #generate desired message by xoring padding and last message and current new character
            msg[i] = c ^ (BLOCK_SIZE - i)
            iv = arrayXor (iv, padding)
            iv = arrayXor (iv, msg)

            #ask oracle
            if probe(iv.hex(), ct.hex()):
                #save actuall padding
                if c >= 1 and c <= 16:
                    pad_value = c

                msg[i]    = c                                                                #save character for next round
                blocktext = printable(c) + blocktext                                         #save current block plaintext
                print(f"  {c:02x} ({printable(c)}) {iv.hex()}  |  {plaintext}{blocktext}")   #somehwat pretty print
                iv = old_iv                                                                  #restore iv
                break
            else:
                print(f"  {c:02x} ({printable(c)}) {iv.hex()}  |  {plaintext}{blocktext}", end="\r") #somehwat pretty print
                iv = old_iv                                                                  #restore iv

    plaintext += blocktext  #update entire plaintext

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