import chat
from VirgilSDK import virgilhub, helper
import VirgilSDK.virgil_crypto.cryptolib as cryptolib

# Encrypt json serialized data using recipient public key downloaded from
# virgil key service
def encrypt_message(json_data, recipient):
    card = virgil_hub.virgilcard.search_app(recipient)[0]
    card_key = card['public_key']['public_key']
    card_id = card['id']
    encrypted = bytearray(cryptolib.CryptoWrapper.encrypt(json_data, card_id, card_key))
    return encrypted


# Initialization virgil application
def virgil_init(token, ident_link, virgil_card_link, private_key_link):
    virgil_hub = virgilhub.VirgilHub(token, ident_link, virgil_card_link, private_key_link)
    return virgil_hub


# Sign message using sender's private key 'prkey' and private key password 'passw'
def sign_message(message, prkey, passw):
    sign = cryptolib.CryptoWrapper.sign(message, prkey, passw)
    return sign


# Decrypt received message 'encrypted' using private key 'prkey' and key password 'passw'
def decrypt_message(encrypted, card_id, prkey, passw):
    decrypted = cryptolib.CryptoWrapper.decrypt(encrypted, card_id, prkey, passw)
    json_data = helper.Helper.json_loads(str(bytearray(decrypted)))
    return json_data


# Verify signature in json serialized data 'json_data' using sender identity 'sender'
def verify_signature(json_data, sender):
    card = virgil_hub.virgilcard.search_app(sender)[0]
    card_key = card['public_key']['public_key']
    is_signed = cryptolib.CryptoWrapper.verify(json_data['message'], json_data['signature'], card_key)
    if not is_signed:
        raise ValueError('Signature is invalid!')


# Sending signed and encrypted message to the chat room
def send_message(my_chat, message, recipient, prkey, passw, sender):
    sign = sign_message(message, prkey, passw)
    data = {'message': message,
            'signature': helper.base64.b64encode(str(bytearray(sign))),
            'sender': sender}
    json_data = helper.Helper.json_dumps(data)
    encrypted = encrypt_message(json_data, recipient)
    my_chat.post_message(encrypted)


# get last messages from chat
# my_chat - chat room
# last_message_id - last received message
# prkey - private key using for decryption
# passw - private key's password
# card_id - server's virgil card id
def get_messages(my_chat, last_message_id, prkey, passw, card_id):
    messages = my_chat.get_messages(last_message_id)
    mid = 0
    for message in messages:
        json_data = decrypt_message(message['message'], card_id, prkey, passw)
        verify_signature(json_data, json_data['sender'])
        print('decrypted: ' + json_data['message'])
        mid = message['id']
    return mid

if __name__ == '__main__':
    token = '%TOKEN%'
    ident_link = 'https://identity.virgilsecurity.com/v1'
    virgil_card_link = 'https://keys.virgilsecurity.com/v3'
    private_key_link = 'https://keyring.virgilsecurity.com/v3'
    virgil_hub = virgil_init(token, ident_link, virgil_card_link, private_key_link)

    sender_identity = '%SENDER_IDENTITY%'
    recipient_identity = '%RECIPIENT_IDENTITY%'
    my_chat = chat.Chat('http://198.211.127.242:4000', '%CHAT_ROOM%', sender_identity)
    message = 'hello world'
    prkey = '%PRIVATE_KEY%'
    passw = '%PRIVATE_KEY_PASSWORD%'

    send_message(my_chat, message, recipient_identity, prkey, passw, sender_identity)
    mid = get_messages(my_chat, 0, prkey, passw, '%RECIPIENT_CARD_ID%')



