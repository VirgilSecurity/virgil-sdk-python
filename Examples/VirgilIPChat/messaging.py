from chat import Chat
from config import *
from operator import itemgetter
from VirgilSDK import virgilhub, helper

import VirgilSDK.virgil_crypto.cryptolib as cryptolib
import os


# Encrypt json serialized data using recipient public key downloaded from
# virgil key service
def encrypt_then_sign_message(text, recipients, private_key, private_key_password):

    cipher = cryptolib.crypto_helper.VirgilCipher()
    for recipient in recipients:

        recipient_id = cryptolib.CryptoWrapper.strtobytes(recipient['id'])
        recipient_pubkey = cryptolib.CryptoWrapper.strtobytes(
            cryptolib.base64.b64decode(recipient['public_key']['public_key']).decode())

        cipher.addKeyRecipient(recipient_id, recipient_pubkey)

    encrypted_message = cipher.encrypt(cryptolib.CryptoWrapper.strtobytes(text), True)
    encrypted_message_base64 = helper.base64.b64encode(bytearray(encrypted_message))

    message_signature = cryptolib.CryptoWrapper.sign(encrypted_message_base64, private_key, private_key_password)

    encrypted_message_model = {
       'message': encrypted_message_base64,
       'sign': helper.base64.b64encode(bytearray(message_signature))
    }

    return encrypted_message_model


# Decrypt received message 'encrypted' using private key 'private_key' and key password 'private_key_password'
def verify_then_decrypt_message(chat_message_model, card_id, private_key, private_key_password):

    # extract message & message signature from chat message DTO.

    sender_identity = chat_message_model['sender_identifier']
    encrypted_message_base64 = chat_message_model['message']
    message_signature_base64 = chat_message_model['sign']

    encrypted_message = bytearray(helper.base64.b64decode(encrypted_message_base64))

    # gets the sender's Virgil Card to be used for message
    # signature validation

    sender_card = get_card_by_identity(sender_identity)
    sender_public_key = sender_card['public_key']['public_key']

    is_valid = cryptolib.CryptoWrapper.verify(encrypted_message_base64,
                                              message_signature_base64,
                                              sender_public_key)
    if not is_valid:
        print('The message signature is not valid.')

    try:
        message = cryptolib.CryptoWrapper.decrypt(encrypted_message,
                                                  card_id,
                                                  private_key,
                                                  private_key_password)

    except Exception as ex:
        return 'Message cannot be decrypted.'


    return str(bytearray(message))


# Gets the actual Virgil Card for specified identity
# identity - The identity value of the member.
def get_card_by_identity(identity):

    identity_cards = virgil_hub.virgilcard.search_card(identity, include_unauthorized=True)
    if identity_cards:

        sorted_cards = sorted(identity_cards, key=itemgetter('created_at'))
        return sorted_cards[-1]


# initializes a new instance of Virgil Hub class that provide
# methods to work with Virgil Security Services.
def init_virgil_hub():

    return virgilhub.VirgilHub(VIRGIL_ACCESS_TOKEN,
                               VIRGIL_IDENTITY_SERVER_URL,
                               VIRGIL_KEYS_SERVICE_URL,
                               VIRGIL_PRIVATE_KEY_SERVICE_URL)


# Gets channel members Virgil Cards
# chat_channel = the current chat channel
def get_chat_members_cards(chat_channel):
    members = chat_channel.channel_members()

    found_cards = []
    for member in members:
        found_cards.append(get_card_by_identity(member['identifier']))


    return found_cards


# Loads a Private Key from file by specified path.
# file_path - the path to file with Private Key
def load_user_pass(file_path):
    if os.path.exists(virgil_key_path):
        return helper.Helper.json_loads(open(file_path, 'r').read())


# Saves a Private Key with information about Virgil Card to specified file path
# file_path - the path to file with Private Key
# virgil_pass - represents information about Virgil Card and Private Key
def save_virgil_pass(file_path, virgil_pass):
    dir_name = os.path.split(virgil_key_path)[0]

    if not os.path.exists(dir_name):
        os.mkdir(os.path.dirname(file_path))

    open(virgil_key_path, 'w').write(helper.Helper.json_dumps(virgil_pass))


if __name__ == '__main__':

    print("Initializing...")

    virgil_key_path = os.path.join(os.environ['HOME'], '.virgil', 'user.virgilpass')
    virgil_hub = init_virgil_hub()

    user_pass = load_user_pass(virgil_key_path)

    if not user_pass:

        # generate a new Public/Private key pair using Virgil
        # Crypto library.

        user_key_pair = cryptolib.CryptoWrapper.generate_keys(
            cryptolib.crypto_helper.VirgilKeyPair.Type_EC_Curve25519, USER_PRIVATE_KEY_PASSWORD)

        # publish newly generated Public Key as a Virgil Card
        # to the Virgil Keys Service.

        user_card = virgil_hub.virgilcard.create_card('email',
                                                      USER_IDENTITY,
                                                      None,
                                                      None,
                                                      user_key_pair['private_key'],
                                                      USER_PRIVATE_KEY_PASSWORD,
                                                      user_key_pair['public_key'])

        user_pass['card_id'] = user_card['id']
        user_pass['identity'] = user_card['identity']['value']
        user_pass['identity_type'] = user_card['identity']['type']
        user_pass['private_key'] = user_key_pair['private_key']
        user_pass['public_key'] = user_key_pair['public_key']

        # save a Private Key with information about Virgil Card
        # to the file on the disk.

        save_virgil_pass(virgil_key_path, user_pass)

    # create and join to the chat channel DEMO.

    chat_channel = Chat(CHAT_API_URL, 'DEMO', user_pass['identity'])

    # get and display all previous messages from channel history.

    messages = chat_channel.get_messages(None)

    if messages:
        print("Messages({})".format(len(messages)))
        for chat_message in messages:

            # verify the message and decrypt it in case if massage
            # signature is valid.

            message_text = verify_then_decrypt_message(chat_message,
                                                       user_pass['card_id'],
                                                       user_pass['private_key'],
                                                       USER_PRIVATE_KEY_PASSWORD)

            print('{0}: {1}'.format(chat_message['sender_identifier'], message_text))

    message_text = raw_input("Input your message here:\n")
    members_cards = get_chat_members_cards(chat_channel)

    encrypted_message_model = encrypt_then_sign_message(message_text,
                                                        members_cards,
                                                        user_pass['private_key'],
                                                        USER_PRIVATE_KEY_PASSWORD)

    chat_channel.post_message(encrypted_message_model)