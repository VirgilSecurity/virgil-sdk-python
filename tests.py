from VirgilSDK import virgilhub
import VirgilSDK.virgil_crypto.cryptolib as cryptolib


def test_search_app(value):
    app_card = virgil_hub.virgilcard.search_app(value)
    print(app_card)
    assert app_card[0]['identity']['value'] == value, 'We`ve got a problem'


def test_search_card(value):
    card = virgil_hub.virgilcard.search_card(value)
    print(card)
    assert card[0]['identity']['value'] == value, 'We`ve got a problem'


def test_verify_identity(type, value):
    ver_res = virgil_hub.identity.verify(type, value)
    print(ver_res)
    assert ver_res['action_id'], 'We`ve got a problem'


def test_confirm_identity(type, value):
    ver_res = virgil_hub.identity.verify(type, value)
    conf_res = virgil_hub.identity.confirm(input('Enter confirmation code:'), ver_res['action_id'])
    print(conf_res)
    assert conf_res['validation_token'], 'We`ve got a problem'


def test_create_card(type, value, keys, private_key_pswd):
    verifyResponse = virgil_hub.identity.verify(type, value)
    identResponse = virgil_hub.identity.confirm(input('Enter confirmation code:'), verifyResponse['action_id'])
    data = {'name': 'Test', 'Organization': 'Test'}
    card = virgil_hub.virgilcard.create_card(type, value, data, identResponse['validation_token'],
                                             keys['private_key'], private_key_pswd, keys['public_key'])
    print(card)
    assert card['id'], 'We`ve got a problem'
    return card


def test_get_card(card_id):
    card = virgil_hub.virgilcard.get_virgil_card(card_id)
    print(card)
    assert card['id'] == card_id, 'We`ve got a problem'


def test_sign_card(signed_card, signer_card, private_key, password):
    sign = virgil_hub.virgilcard.sign_card(signed_card, signer_card, private_key, password)
    print(sign)
    assert sign['signed_digest'], 'We`ve got a problem'


def test_unsign_card(signed_card, signer_card, private_key, password):
    unsign = virgil_hub.virgilcard.unsign_card(signed_card, signer_card, private_key, password)
    print(unsign)
    assert unsign == 'Unsigned!', 'We`ve got a problem'


def test_load_private_key(private_key, card_id, password):
    recipient_card = virgil_hub.virgilcard.search_app(('com.virgilsecurity.private-keys'))
    response = virgil_hub.privatekey.load_private_key(recipient_card[0]['public_key']['public_key'], recipient_card[0]['id'],
                                                 private_key, card_id, password)
    assert response == '[]', 'We`ve got a problem'


def test_grab_private_key(type, value, password, card_id):
    recipient_card = virgil_hub.virgilcard.search_app(('com.virgilsecurity.private-keys'))
    verifyResponse = virgil_hub.identity.verify(type, value)
    identResponse = virgil_hub.identity.confirm(input('Enter confirmation code:'), verifyResponse['action_id'])
    response = virgil_hub.privatekey.grab_private_key(recipient_card[0]['public_key']['public_key'],
                                                                      recipient_card[0]['id'], type, value,
                                                                      identResponse['validation_token'], password,
                                                                      card_id)
    assert response['private_key'], 'We`ve got a problem'


def test_delete_private_key(private_key, card_id, password):
    recipient_card = virgil_hub.virgilcard.search_app(('com.virgilsecurity.private-keys'))
    response = virgil_hub.privatekey.delete_private_key(recipient_card[0]['public_key']['public_key'], recipient_card[0]['id'],
                                                        private_key, card_id, password)
    assert response == '[]', 'We`ve got a problem'


def test_get_public_key(key_id, signer_card_id, private_key, password):
    response = virgil_hub.virgilcard.get_public_key(key_id, True, signer_card_id, private_key, password)
    print(response)
    assert response['id'] == key_id, 'We`ve got a problem'


def test_delete_card(type, value, card_id, private_key, password):
    verifyResponse = virgil_hub.identity.verify(type, value)
    identResponse = virgil_hub.identity.confirm(input('Enter confirmation code:'), verifyResponse['action_id'])
    response = virgil_hub.virgilcard.delete_card(type, value, identResponse['validation_token'], card_id, private_key,
                                                 password)
    assert response == '', 'We`ve got a problem'


if __name__ == '__main__':
    token = '%TOKEN%'
    ident_link = 'https://identity-stg.virgilsecurity.com/v1'
    virgil_card_link = 'https://keys-stg.virgilsecurity.com/v3'
    private_key_link = 'https://keyring-stg.virgilsecurity.com/v3'

    virgil_hub = virgilhub.VirgilHub(token, ident_link, virgil_card_link, private_key_link)

    # Search application
    value = '%VALUE&'
    test_search_app(value)

    # Search card
    value = '%IDENTITY_VALUE%'
    test_search_card(value)

    # Confirmation and validation identity
    type = '%IDENTITY_TYPE%'
    value = '%IDENTITY_VALUE%'
    test_verify_identity(type, value)
    test_confirm_identity(type, value)

    # Create new test card
    Passwd = '12345678'
    keys = cryptolib.CryptoWrapper.generate_keys(cryptolib.crypto_helper.VirgilKeyPair.Type_Default, Passwd)
    my_new_card = test_create_card(type, value, keys, Passwd)

    # Get card by id
    test_get_card(my_new_card['id'])

    # Sign virgil card
    prkey = '%SIGNER_PRIVATE_KEY%'
    passw = '%SIGNER_PASSWORD%'
    signer_card_id = "%SIGNER_CARD_ID%"
    test_sign_card(my_new_card['id'], signer_card_id, prkey, passw)

    # Unsign virgil card
    test_unsign_card(my_new_card['id'], signer_card_id, prkey, passw)

    # Load private key
    test_load_private_key(keys['private_key'], my_new_card['id'], Passwd)

    # Get private key
    test_grab_private_key(type, value, Passwd, my_new_card['id'])

    # Delete private key
    test_delete_private_key(keys['private_key'], my_new_card['id'], Passwd)

    # Get public key
    test_get_public_key(my_new_card['public_key']['id'], signer_card_id, prkey, passw)

    # Delete card
    test_delete_card(type, value, my_new_card['id'], keys['private_key'], Passwd)
