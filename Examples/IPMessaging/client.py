# Client send encrypted messages to the server
# Each message signed with client's private key
# After signing massage encrypted with server's public key and sending
# In case of successfully decryption and signature verification server returns message as a plaintext

from socket import *
from VirgilSDK import virgilhub, helper
import VirgilSDK.virgil_crypto.cryptolib as cryptolib


# Initialization virgil application
def virgil_init(token, ident_link, virgil_card_link, private_key_link):
    virgil_hub = virgilhub.VirgilHub(token, ident_link, virgil_card_link, private_key_link)
    return virgil_hub


# Sign message using sender's private key 'prkey' and private key password 'passw'
def sign_message(message, prkey, passw):
    sign = cryptolib.CryptoWrapper.sign(message, prkey, passw)
    return sign


# Encrypt json serialized data using recipient public key downloaded from
# virgil key service
def encrypt_message(json_data, recipient):
    card = virgil_hub.virgilcard.search_card(recipient)[0]
    card_key = card['public_key']['public_key']
    card_id = card['id']
    encrypted = bytearray(cryptolib.CryptoWrapper.encrypt(json_data, card_id, card_key))
    return encrypted


# Sending signed and encrypted message to the server
def send_to_server(message, server_identity, prkey, passw, sender):
    sign = sign_message(message, prkey, passw)
    data = {'message': message,
            'signature': helper.base64.b64encode(str(bytearray(sign))),
            'sender': sender}
    json_data = helper.Helper.json_dumps(data)
    encrypted = encrypt_message(json_data, server_identity)

    host = 'localhost'
    port = 80
    ip_channel = socket(AF_INET, SOCK_STREAM)
    ip_channel.connect((host, port))
    ip_channel.send(encrypted)
    data = ip_channel.recv(1024)
    print('Client received: ' + str(data))
    ip_channel.close()


if __name__ == '__main__':
    token = '%TOKEN%'
    ident_link = 'https://identity-stg.virgilsecurity.com/v1'
    virgil_card_link = 'https://keys-stg.virgilsecurity.com/v3'
    private_key_link = 'https://keyring-stg.virgilsecurity.com/v3'
    virgil_hub = virgil_init(token, ident_link, virgil_card_link, private_key_link)

    message = 'hello world'
    prkey = '%SENDER_PRIVATE_KEY%'
    passw = '%SENDER_PRIVATE_KEY_PASSWORD%'

    send_to_server(message, '%RECIPIENT_IDENTITY%', prkey, passw, '%SENDER_IDENTITY%')
