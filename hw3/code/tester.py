import requests
import time


def printHex(byte_data):
    for byte in byte_data:
        print(f"{byte:02x}", end="")
    print("")

def arrayXor(array_a, array_b):
    return bytes([a ^ b for a, b in zip(array_a, array_b)])


#encrypted_command = bytearray.fromhex("")
#encrypted_command = bytearray.fromhex("")
#encrypted_command = bytearray.fromhex("")
#encrypted_command = bytearray.fromhex("")
#encrypted_command = bytearray.fromhex("")
#encrypted_command = bytearray.fromhex("0db2ba796aac9be203c74bf71a801947a3a39d3771c736c3564d76cb97a0cc146f9eb07b38e53608eedfffdf248e8fb03d7f77400ab705759e018e2d0b3b44b7589c3445f7d7734feb487c90986be88c5c874cf7b37d69a928cf89761b0d2841f810279ba27adb9deec8030b54987c4aa8579af443c9cde1f6c9485c97")
#encrypted_command = bytearray.fromhex("bf0732d53c4d3e34a10bf15e7a4329fe6ff68461f4db4105a8f66ec25bef3d6dffb77ede55de25621b45f1f187585058ce15135c3d4a7758a57fb83b0348985e77a6fd6b66476d9e340b11ba42d5dcd0bae4195c60b35c35c24f8687480d2841f810279ba27adb9deec8030b54987c4aa8579af443c9cde1f6c9485c97")
#encrypted_command = bytearray.fromhex("77546837aa048d02e1d82739f9e48bbaeb51e89a688afb20f4a2b520708049047eed9bddaddb10a648afe49bb5033835675c93a96e9804c0e9ae3ed0695ba41e33aa5997395d097e2c44fd9bdf3619568acd5b7416da3fe42d1bc78fb60d2841f810279ba27adb9de7c20c0459987c4aa8579af443c9cde1f6c9485c97")
encrypted_command = bytearray.fromhex("90114b93f9632a82fde0b5ad730c8ace442b673b3bc27cfafd205dbdc8d799bb4ec9f837f91a308066675624a677488373ecfa5fb4316e150574f733a473b0687aaf0f97291fb1335c8d45b08a7a30b4b1653fe531069d01d37591c5c50d2841f810279ba27adb9deec8030b54987c4aa8579af443c9cde1f6c9485c97")

nonce = encrypted_command[:16]
ctr   = encrypted_command[16:-32]
iv    = encrypted_command[-32:-16]
mac   = encrypted_command[-16:]

print(f"Nonce ({len(nonce)}):")
printHex(nonce)
print(f"CTR ({len(ctr)}):")
printHex(ctr)
print(f"IV ({len(iv)}):")
printHex(iv)
print(f"MAC ({len(mac)}):")
printHex(mac)

#send last nonce with counter 0
#we should get hash of it in MAC -> xor with first block of msg -> raw text?

blocks = -(-len(ctr)//16)
print(f"Blocks: {blocks}")

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
    start = i * 16
    end   = (i + 1) * 16
    if end > len(ctr):
        end = len(ctr)
    #xor it with nth block of ctr hash to get plaintext
    decrypted_block = arrayXor(nonce_hash, ctr[start:end])
    decrypted_msg += f"{decrypted_block.decode()}"

    #increment counter (nonce with counter)
    nonce = int(nonce.hex(), 16)
    nonce += 1
    nonce = bytearray.fromhex(f"{nonce:x}")

forged_msg = decrypted_msg[:10] + "492875" + decrypted_msg[16:]

print(f"Decrypted msg: {decrypted_msg}")
print(f"Forged msg:    {forged_msg}")
