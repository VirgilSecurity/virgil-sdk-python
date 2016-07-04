from chat import Chat
from config import *
from operator import itemgetter
from VirgilSDK import virgilhub, helper

import VirgilSDK.virgil_crypto.cryptolib as cryptolib
import os


# Signs and encrypts the outgoing message
# text - the message text to be encrypted
# recipients - the message recipients
# private_key - the user's private key
# private_key_password - the user's private key password
def sign_then_encrypt_message(text, recipients, private_key, private_key_password):

    # sign the original message with user's private key
    message_signature = cryptolib.CryptoWrapper.sign(text, private_key, private_key_password)

    # encrypt the original message for channel's members using
    # theirs public keys
    cipher = cryptolib.crypto_helper.VirgilCipher()
    for recipient in recipients:

        recipient_id = cryptolib.CryptoWrapper.strtobytes(recipient['id'])
        recipient_pubkey = cryptolib.CryptoWrapper.strtobytes(
            cryptolib.base64.b64decode(recipient['public_key']['public_key']).decode())

        cipher.addKeyRecipient(recipient_id, recipient_pubkey)

    encrypted_message = cipher.encrypt(cryptolib.CryptoWrapper.strtobytes(text), True)

    # return a model with encrypted message and the signature
    chat_message_model = {
       'message': helper.base64.b64encode(bytearray(encrypted_message)),
       'sign': helper.base64.b64encode(bytearray(message_signature))
    }

    return chat_message_model


# Decrypts and verify the message received from Chat API
# chat_message_model - the message DTO model
# card_id - the id of the Virgil Card of the message sender
# private_key - the user's private key
# private_key_password - the user's private key password
def decrypt_then_verify_message(chat_message_model, card_id, private_key, private_key_password):

    # extract message & message signature from received message model.
    encrypted_message = bytearray(helper.base64.b64decode(chat_message_model['message']))

    try:
        # decrypt the message with user's private key
        message_data = cryptolib.CryptoWrapper.decrypt(encrypted_message, card_id, private_key, private_key_password)
        message = str(bytearray(message_data))

        # get a sender's Virgil Card to be used for signature validation
        sender_card = get_card_by_identity(chat_message_model['sender_identifier'])
        sender_public_key = sender_card['public_key']['public_key']

        # validate the signature of original message using sender's public key
        is_valid = cryptolib.CryptoWrapper.verify(message, chat_message_model['sign'], sender_public_key)
        if not is_valid:
            return '{} (signature is not valid)'.format(message)

        return message

    except Exception:
        return 'Message cannot be decrypted.'


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
    if os.path.exists(VIRGIL_PRIVATE_KEY_PATH):
        return helper.Helper.json_loads(open(file_path, 'r').read())


# Saves a Private Key with information about Virgil Card to specified file path
# file_path - the path to file with Private Key
# virgil_pass - represents information about Virgil Card and Private Key
def save_virgil_pass(file_path, virgil_pass):
    dir_name = os.path.normpath(os.path.split(VIRGIL_PRIVATE_KEY_PATH)[0])

    if not os.path.exists(dir_name):
        try:
            os.makedirs(os.path.dirname(file_path))
        except OSError:
            # Directory already created
            pass

    open(VIRGIL_PRIVATE_KEY_PATH, 'w').write(helper.Helper.json_dumps(virgil_pass))


if __name__ == '__main__':

    print("Initializing...")

    virgil_hub = init_virgil_hub()

    user_pass = load_user_pass(VIRGIL_PRIVATE_KEY_PATH)

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

        user_pass = {
            'card_id': user_card['id'],
            'identity': user_card['identity']['value'],
            'identity_type': user_card['identity']['type'],
            'private_key': user_key_pair['private_key'],
            'public_key': user_key_pair['public_key']
        }

        # save a Private Key with information about Virgil Card
        # to the file on the disk.

        save_virgil_pass(VIRGIL_PRIVATE_KEY_PATH, user_pass)

    # create and join to the chat channel DEMO.

    chat_channel = Chat(CHAT_API_URL, 'DEMO', user_pass['identity'])

    # get and display all previous messages from channel history.

    messages = chat_channel.get_messages(None)

    if messages:
        print("Messages({})".format(len(messages)))
        for chat_message in messages:

            # verify the message and decrypt it in case if massage
            # signature is valid.

            message_text = decrypt_then_verify_message(chat_message,
                                                       user_pass['card_id'],
                                                       user_pass['private_key'],
                                                       USER_PRIVATE_KEY_PASSWORD)

            print('{0}: {1}'.format(chat_message['sender_identifier'], message_text))

    message_text = raw_input("Input your message here:\n")
    members_cards = get_chat_members_cards(chat_channel)

    encrypted_message_model = sign_then_encrypt_message(message_text,
                                                        members_cards,
                                                        user_pass['private_key'],
                                                        USER_PRIVATE_KEY_PASSWORD)

    chat_channel.post_message(encrypted_message_model)
