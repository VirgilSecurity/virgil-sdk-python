from VirgilSDK import virgilhub
import VirgilSDK.virgil_crypto.cryptolib as cryptolib
import VirgilSDK.helper as helper
import mailinator
import time
from config import *
import random



def test_search_app(value):
    app_card = virgil_hub.virgilcard.search_app(value)
    # print(app_card)
    assert app_card[0]['identity']['value'] == value, 'We`ve got a problem'


def test_search_card(value):
    card = virgil_hub.virgilcard.search_card(value)
    # print(card)
    assert card[0]['identity']['value'] == value, 'We`ve got a problem'


def test_verify_identity(type, value):
    ver_res = virgil_hub.identity.verify(type, value)
    # print(ver_res)
    assert ver_res['action_id'], 'We`ve got a problem'


def test_confirm_identity(type, value):
    ver_res = virgil_hub.identity.verify(type, value)
    mailinator_token = MAILINATOR_TOKEN
    code = ''
    for i in range(3):
        try:
            code = mailinator.receive_code(mailinator_token, value)
            if code != '':
                break
            time.sleep(10)
        except:
            pass
    conf_res = virgil_hub.identity.confirm(code, ver_res['action_id'], 3)
    # print(conf_res)
    assert conf_res['validation_token'], 'We`ve got a problem'
    return conf_res['validation_token']


def test_create_card(type, value, keys, private_key_pswd, val_token):
    data = {'name': 'Test', 'Organization': 'Test'}
    card = virgil_hub.virgilcard.create_card(type, value, data, val_token,
                                             keys['private_key'], private_key_pswd, keys['public_key'])
    # print(card)
    assert card['id'], 'We`ve got a problem'
    return card


def test_get_card(card_id):
    card = virgil_hub.virgilcard.get_virgil_card(card_id)
    # print(card)
    assert card['id'] == card_id, 'We`ve got a problem'


def test_sign_card(signed_card, signer_card, private_key, password):
    sign = virgil_hub.virgilcard.sign_card(signed_card, signer_card, private_key, password)
    # print(sign)
    assert sign['signed_digest'], 'We`ve got a problem'


def test_unsign_card(signed_card, signer_card, private_key, password):
    unsign = virgil_hub.virgilcard.unsign_card(signed_card, signer_card, private_key, password)
    # print(unsign)
    assert unsign == 'Unsigned!', 'We`ve got a problem'


def test_load_private_key(private_key, card_id, password):
    recipient_card = virgil_hub.virgilcard.search_app(('com.virgilsecurity.private-keys'))
    response = virgil_hub.privatekey.load_private_key(recipient_card[0]['public_key']['public_key'], recipient_card[0]['id'],
                                                 private_key, card_id, password)
    assert response == '[]', 'We`ve got a problem'


def test_grab_private_key(type, value, password, card_id, val_token):
    recipient_card = virgil_hub.virgilcard.search_app(('com.virgilsecurity.private-keys'))
    response = virgil_hub.privatekey.grab_private_key(recipient_card[0]['public_key']['public_key'],
                                                                      recipient_card[0]['id'], type, value,
                                                                      val_token, password,
                                                                      card_id)
    assert response['private_key'], 'We`ve got a problem'


def test_delete_private_key(private_key, card_id, password):
    recipient_card = virgil_hub.virgilcard.search_app(('com.virgilsecurity.private-keys'))
    response = virgil_hub.privatekey.delete_private_key(recipient_card[0]['public_key']['public_key'], recipient_card[0]['id'],
                                                        private_key, card_id, password)
    assert response == '[]', 'We`ve got a problem'


def test_get_public_key(key_id, signer_card_id, private_key, password):
    response = virgil_hub.virgilcard.get_public_key(key_id, True, signer_card_id, private_key, password)
    # print(response)
    assert response['id'] == key_id, 'We`ve got a problem'


def test_delete_card(type, value, card_id, private_key, password, val_token):
    response = virgil_hub.virgilcard.delete_card(type, value, val_token, card_id, private_key,
                                                 password)
    assert response == '', 'We`ve got a problem'


if __name__ == '__main__':
    token = VIRGIL_APPLICATION_TOKEN
    ident_link = 'https://identity-stg.virgilsecurity.com/v1'
    virgil_card_link = 'https://keys-stg.virgilsecurity.com/v3'
    private_key_link = 'https://keys-private-stg.virgilsecurity.com/v3'

    virgil_hub = virgilhub.VirgilHub(token, ident_link, virgil_card_link, private_key_link)

    # Search application
    print('Trying to search Virgil application..')
    application_value = APPLICATION_VALUE
    test_search_app(application_value)
    print('Result: Successful')

    # Confirmation and validation identity
    print('Trying to confirm identity..')
    type = helper.IdentityType.email
    value = IDENTITY_VALUE + str(random.randint(0, 100)) + '@mailinator.com'
    print(value)
    val_token = test_confirm_identity(type, value)
    print('Result: Successful')

    # Create new test card
    print('Trying to create Virgil card..')
    Passwd = NEW_CARD_PASSWORD
    keys = cryptolib.CryptoWrapper.generate_keys(cryptolib.crypto_helper.VirgilKeyPair.Type_Default, Passwd)
    my_new_card = test_create_card(type, value, keys, Passwd, val_token)
    print('Result: Successful')

    # Search card
    print('Trying to search Virgil card..')
    test_search_card(value)
    print('Result: Successful')

    # Get card by id
    print('Trying to get Virgil card by ID..')
    test_get_card(my_new_card['id'])
    print('Result: Successful')
    """
    # Sign virgil card
    print('Trying to sign Virgil card..')
    prkey = PRIVATE_KEY
    passw = PRIVATE_KEY_PASSWORD
    signer_card_id = APPLICATION_CARD_ID
    test_sign_card(my_new_card['id'], signer_card_id, prkey, passw)
    print('Result: Successful')

    # Unsign virgil card
    print('Trying to unsign Virgil card..')
    test_unsign_card(my_new_card['id'], signer_card_id, prkey, passw)
    print('Result: Successful')
    """
    # Load private key
    print('Trying to upload private key..')
    test_load_private_key(keys['private_key'], my_new_card['id'], Passwd)
    print('Result: Successful')

    # Get private key
    print('Trying to download private key..')
    test_grab_private_key(type, value, Passwd, my_new_card['id'], val_token)
    print('Result: Successful')

    # Delete private key
    print('Trying to delete prvate key..')
    test_delete_private_key(keys['private_key'], my_new_card['id'], Passwd)
    print('Result: Successful')

    # Get public key
    print('Trying to get public key by ID..')
    test_get_public_key(my_new_card['public_key']['id'], my_new_card['id'], keys['private_key'], Passwd)
    print('Result: Successful')

    # Delete card
    print('Trying to delete Virgil card..')
    test_delete_card(type, value, my_new_card['id'], keys['private_key'], Passwd, val_token)
    print('Result: Successful')

