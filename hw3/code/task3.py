import requests
import time


def printHex(byte_data):
    for byte in byte_data:
        print(f"{byte:02x}", end="")
    print("")

def arrayXor(array_a, array_b):
    return bytes([a ^ b for a, b in zip(array_a, array_b)])


encrypted_command = bytearray.fromhex("77546837aa048d02e1d82739f9e48bbaeb51e89a688afb20f4a2b520708049047eed9bddaddb10a648afe49bb5033835675c93a96e9804c0e9ae3ed0695ba41e33aa5997395d097e2c44fd9bdf3619568acd5b7416da3fe42d1bc78fb60d2841f810279ba27adb9de7c20c0459987c4aa8579af443c9cde1f6c9485c97")

nonce = encrypted_command[:16]
print(nonce.hex())
ctr   = encrypted_command[16:-32]
iv    = encrypted_command[-32:-16]
mac   = encrypted_command[-16:]

blocks = -(-len(ctr)//16)
print(f"CRT blocks: {blocks}")

#decrypt message
decrypted_msg = ""
for i in range(0, blocks):
    response = requests.get("https://pv079.fi.muni.cz/encrypt", params={"msg":nonce.hex(), "iv":"00" * 16},)
    time.sleep(0.25)

    if response.status_code != 200:
        print(f"Error ({response.status_code}): {response.raw}")
        exit(0)
    
    #extract nonce hash
    nonce_hash = bytearray.fromhex(response.json()["result"])[-16:]
    print(response.json())
    start = i * 16
    end   = (i + 1) * 16
    if end > len(ctr):
        end = len(ctr)
    print(start)
    print(end)
    #xor it with nth block of ctr hash to get plaintext
    decrypted_block = arrayXor(nonce_hash, ctr[start:end])
    decrypted_msg += f"{decrypted_block.decode()}"
    print(decrypted_block)

    #increment counter (nonce with counter)
    nonce = int(nonce.hex(), 16)
    nonce += 1
    nonce = bytearray.fromhex(f"{nonce:032x}")

forged_msg = decrypted_msg[:10] + "492875" + decrypted_msg[16:]

print(f"Decrypted msg: {decrypted_msg}")
print(f"Forged msg:    {forged_msg}")

response = requests.get("https://pv079.fi.muni.cz/encrypt", params={"msg":forged_msg.encode("utf-8").hex(), "iv":iv.hex()},)
if response.status_code != 200:
    print(f"Error ({response.status_code}): {response.raw}")
    exit(0)

forged_command = response.json()['result']
print(f"Encrypted:\n  {forged_command}")

send_response = requests.post(
    "https://pv079.fi.muni.cz/send",
    data={"encrypted_command":forged_command},)
print(send_response.json())


#to get the same hash, we need to create IV from first block of plaintext, my plaintext and original IV
plain_block = bytearray(decrypted_msg[:16], "utf-8")
xor = arrayXor(iv, plain_block)
forged_block = bytearray(forged_msg[:16], "utf-8")
forged_iv = arrayXor(xor, forged_block)

#resend with proper iv
response = requests.get("https://pv079.fi.muni.cz/encrypt", params={"msg":forged_msg.encode("utf-8").hex(), "iv":forged_iv.hex()},)
if response.status_code != 200:
    print(f"Error ({response.status_code}): {response.raw}")
    exit(0)

forged_command = response.json()['result']
print(f"Encrypted (proper iv):\n  {forged_command}")

send_response = requests.post(
    "https://pv079.fi.muni.cz/send",
    data={"encrypted_command":forged_command},)
print(send_response.json())


#forged_command = bytearray.fromhex(forged_command)
#nonce = forged_command[:16]
#ctr   = forged_command[16:-32]
#iv    = forged_command[-32:-16]
#mac   = forged_command[-16:]
#
#print(f"Nonce ({len(nonce)}):")
#printHex(nonce)
#print(f"CTR ({len(ctr)}):")
#printHex(ctr)
#print(f"IV ({len(iv)}):")
#printHex(iv)
#print(f"MAC ({len(mac)}):")
#printHex(mac)

print("\ndone")
