# Client send encrypted messages to the server
# Each message signed with client's private key
# After signing massage encrypted with server's public key and sending
# In case of successfully decryption and signature verification server returns message as a plaintext

from socket import *
from VirgilSDK import virgilhub, helper
import VirgilSDK.virgil_crypto.cryptolib as cryptolib

token = '%TOKEN%'
ident_link = 'https://identity-stg.virgilsecurity.com/v1'
virgil_card_link = 'https://keys-stg.virgilsecurity.com/v3'
private_key_link = 'https://keyring-stg.virgilsecurity.com/v3'
virgil_hub = virgilhub.VirgilHub(token, ident_link, virgil_card_link, private_key_link)

message = 'hello world'
prkey = '%SENDER_PRIVATE_KEY%'
passw = '%PRIVATE_KEY_PASSWORD%'
sign = cryptolib.CryptoWrapper.sign(message, prkey, passw)

data = {'message': message,
        'signature': helper.base64.b64encode(str(bytearray(sign)))}
json_data = helper.Helper.json_dumps(data)


card = virgil_hub.virgilcard.search_card('%RECIPIENT%')[0]
card_key = card['public_key']['public_key']
card_id = card['id']
encrypted = bytearray(cryptolib.CryptoWrapper.encrypt(json_data, card_id, card_key))
host = 'localhost' 
port = 80
ip_channel = socket(AF_INET, SOCK_STREAM) 
ip_channel.connect((host, port)) 
ip_channel.send(encrypted) 
data = ip_channel.recv(1024) 
print('Client received: ' + str(data)) 
ip_channel.close() 
