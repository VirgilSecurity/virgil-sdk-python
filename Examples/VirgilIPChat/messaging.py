import VirgilIPChat.chat as chat
from VirgilSDK import virgilhub, helper
import VirgilSDK.virgil_crypto.cryptolib as cryptolib


# Encrypt json serialized data using recipient public key downloaded from
# virgil key service
def encrypt_message(json_data, recipient):
    card = virgil_hub.virgilcard.search_card(recipient, type=None, include_unauthorized=True)[0]
    card_key = card['public_key']['public_key']
    card_id = card['id']
    encrypted = helper.base64.b64encode(
        bytearray(cryptolib.CryptoWrapper.encrypt(json_data, card_id, card_key))).decode()
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
    decrypted = cryptolib.CryptoWrapper.decrypt(bytearray(helper.base64.b64decode(encrypted)), card_id, prkey, passw)
    json_data = helper.Helper.json_loads(bytearray(decrypted))
    return json_data


# Verify signature in json serialized data 'json_data' using sender identity 'sender'
def verify_signature(json_data, sender):
    card = virgil_hub.virgilcard.search_card(sender, type=None, include_unauthorized=True)[0]
    card_key = card['public_key']['public_key']
    is_signed = cryptolib.CryptoWrapper.verify(json_data['message'], json_data['signature'], card_key)
    if not is_signed:
        raise ValueError('Signature is invalid!')


# Sending signed and encrypted message to the chat room
def send_message(my_chat, message, recipient, prkey, passw, sender):
    sign = sign_message(message, prkey, passw)
    data = {'message': message,
            'signature': helper.base64.b64encode(bytearray(sign)).decode(),
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
def get_messages(my_chat, last_message_id, prkey, passw, card_id, mess=None):
    messages = my_chat.get_messages(last_message_id)
    mid = 0
    for message in messages:
        json_data = decrypt_message(message['message'], card_id, prkey, passw)
        verify_signature(json_data, json_data['sender'])
        print('decrypted: ' + json_data['message'])
        mid = message['id']
    return mid

if __name__ == '__main__':
    token = '%ACCESS_TOKEN%'
    ident_link = 'https://identity.virgilsecurity.com/v1'
    virgil_card_link = 'https://keys.virgilsecurity.com/v3'
    private_key_link = 'https://keyring.virgilsecurity.com/v3'
    virgil_hub = virgil_init(token, ident_link, virgil_card_link, private_key_link)

    senders_keys = cryptolib.CryptoWrapper.generate_keys(
        cryptolib.crypto_helper.VirgilKeyPair.Type_Default, '%PASSWORD%')
    data = {'Field1': 'Data1', 'Field2': 'Data2'}
    sender_identity = 'test1@test.com'
    new_card = virgil_hub.virgilcard.create_card(virgilhub.IdentityType.email, sender_identity, data,
                                                 None, senders_keys['private_key'],
                                                 '%PASSWORD%', senders_keys['public_key'])

    recipient_keys = cryptolib.CryptoWrapper.generate_keys(cryptolib.crypto_helper.VirgilKeyPair.Type_Default,
                                                           '%PASSWORD%')
    recipient_identity = 'test2@test.com'
    new_card2 = virgil_hub.virgilcard.create_card(virgilhub.IdentityType.email, recipient_identity, data,
                                                  None, recipient_keys['private_key'],
                                                  '%PASSWORD%', recipient_keys['public_key'])
    my_chat = chat.Chat('http://198.211.127.242:4000', 'room1', sender_identity)
    message = 'hello world'

    send_message(my_chat, message, recipient_identity, senders_keys['private_key'], '%PASSWORD%', sender_identity)
    mid = get_messages(my_chat, 0, recipient_keys['private_key'], '%PASSWORD%', new_card2['id'], enc)
    print(mid)



