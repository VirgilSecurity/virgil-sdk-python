# Server side receiving encrypted messages from clients
# Each received message contains encrypted sender's signature
# After decryption sender's card will be find on public key service and signature will be checked
# If signature is correct message will be returned to client as a plaintext

from socket import *
from VirgilSDK import virgilhub, helper
import VirgilSDK.virgil_crypto.cryptolib as cryptolib

token = '%TOKEN%'
ident_link = 'https://identity-stg.virgilsecurity.com/v1'
virgil_card_link = 'https://keys-stg.virgilsecurity.com/v3'
private_key_link = 'https://keyring-stg.virgilsecurity.com/v3'
virgil_hub = virgilhub.VirgilHub(token, ident_link, virgil_card_link, private_key_link)

prkey = '%RECIPIENT_PRIVATE_KEY%'
passw = '%PRIVATE_KEY_PASSWORD%'

host = 'localhost' 
port = 80 
ip_channel = socket(AF_INET, SOCK_STREAM) 
ip_channel.bind((host, port)) 
ip_channel.listen(5) 
while True: 
    connection, address = ip_channel.accept()      
    while True:
        encrypted = connection.recv(1024)
        if not encrypted: break
        card = virgil_hub.virgilcard.search_card('%SENDER%')[0]
        card_key = card['public_key']['public_key']
        card_id = card['id']
        decrypted = cryptolib.CryptoWrapper.decrypt(encrypted, card_id, prkey, passw)
        json_data = helper.Helper.json_loads(str(bytearray(decrypted)))
        is_signed = cryptolib.CryptoWrapper.verify(json_data['message'], json_data['signature'], card_key)
        if not is_signed:
            raise ValueError('Signature is invalid!')
        print(json_data['message'])
        connection.send(b'Server received=>' + json_data['message'])
    connection.close() 
