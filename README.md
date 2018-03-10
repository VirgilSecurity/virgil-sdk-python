# Virgil Security Python SDK
[![PyPI](https://img.shields.io/pypi/v/virgil-sdk.svg)](https://pypi.python.org/pypi/virgil-sdk) [![PyPI](https://img.shields.io/pypi/wheel/virgil-sdk.svg)](https://pypi.python.org/pypi/virgil-sdk) [![PyPI](https://img.shields.io/pypi/pyversions/virgil-sdk.svg)](https://pypi.python.org/pypi/virgil-sdk)



[Introduction](#installation) | [SDK Features](#sdk-features) | [Installation](#installation) | [Initialization](#initialization) | [Usage Examples](#usage-examples) | [Docs](#docs) | [Support](#support)

<img width="230px" src="logo.png" align="left" hspace="10" vspace="6"> [Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application. In a few simple steps you can encrypt communication, securely store data, provide passwordless login, and ensure data integrity.

The Virgil SDK allows developers to get up and running with Virgil API quickly and add full end-to-end security to their existing digital solutions to become HIPAA and GDPR compliant and more.

## SDK Features
- communicate with [Virgil Cards Service][_cards_service]
- manage users' Public Keys
- store private keys in secure local storage
- use Virgil [Crypto library][_virgil_crypto]


## Installation

The Virgil Python SDK is provided as a package named *virgil-sdk*. The package is distributed via Pypi package management system.

To install the pip package use the command below:
```bash
pip install virgil-sdk
```


## Initialization

Be sure that you have already registered at the [Dev Portal](https://developer.virgilsecurity.com/account/signin) and created your application.

To initialize the SDK at the __Client Side__ you need only the __Access Token__ created for a client at Dev Portal. The Access Token helps to authenticate client's requests.

```python
virgil = Virgil("[ACCESS_TOKEN]")
```


To initialize the SDK at the __Server Side__ you need the application credentials (__Access Token__, __App ID__, __App Key__ and __App Key Password__) you got during Application registration at the Dev Portal.

```python
key_file_content = open("[YOUR_APP_KEY_FILEPATH_HERE]", "r").read()
raw_private_key = VirgilCrypto().strtobytes(key_file_content)

creds = Credentials(
    app_id="[YOUR_APP_ID_HERE]",
    app_key=raw_private_key,
    app_password="[YOUR_APP_KEY_PASSWORD_HERE]"
)

context = VirgilContext(
    access_token="[YOUR_ACCESS_TOKEN_HERE]",
    credentials=creds
)
virgil = Virgil(context=context)
```



## Usage Examples

#### Generate and publish user's Cards with Public Keys inside on Cards Service
Use the following lines of code to create and publish a user's Card with Public Key inside on Virgil Cards Service:

```python
# generate a new Virgil Key
alice_key = virgil.keys.generate()

# save the Virgil Key into the storage
alice_key.save("[KEY_NAME]", "[KEY_PASSWORD]")

# create Identity
identity = virgil.identities.create_user("alice")

# create a Virgil Card
alice_card = virgil.cards.create(identity, alice_key)

# export the Virgil Card to string
exported_alice_card = alice_card.export()

# transmit the exported Card to server side
# import the Virgil Card from a string
alice_card = virgil.cards.import_card(exported_alice_card)

# publish the Card on the Cards Service
virgil.cards.publish(alice_card)

```

#### Sign then encrypt data

Virgil SDK lets you use a user's Private key and his or her Cards to sign, then encrypt any kind of data.

In the following example, we load a Private Key from a customized Key Storage and get recipient's Card from the Virgil Cards Services. Recipient's Card contains a Public Key on which we will encrypt the data and verify a signature.


```python
# load a Virgil Key from a device storage
alice_key = virgil.keys.load("[KEY_NAME]", "[OPTIONAL_KEY_PASSWORD]")

# search for Virgil Cards on Cards Service
bob_cards = virgil.cards.find(["bob"])

# prepare a message
message = "Hey Bob, how's it going?"

# sign and encrypt the message
cipher_text = virgil.sign_then_encrypt(message, [alice_key, bob_cards]).to_string("base64")
```

#### Decrypt then verify data
Once the Users receive the signed and encrypted message, they can decrypt it with their own Private Key and verify signature with a Sender's Card:


```python
# load a Virgil Key from a device storage
bob_key = virgil.keys.load("[KEY_NAME]", "[OPTIONAL_KEY_PASSWORD]")

# get a sender's Virgil Card from the Virgil Cards Service
alice_card = virgil.cards.get("[ALICE_CARD_ID]")

cipher_buff = VirgilBuffer.from_string(cipher_text)

# decrypt a message
original_message = bob_key.decrypt_then_verify(cipher_buff, alice_card).to_string()
```


## Docs
Virgil Security has a powerful set of APIs, and the documentation below can get you started today.

In order to use the Virgil SDK with your application, you will need to first configure your application. By default, the SDK will attempt to look for Virgil-specific settings in your application but you can change it during SDK configuration.

* [Configure the SDK][_configure_sdk] documentation
  * [Setup authentication][_setup_authentication] to make API calls to Virgil Services
  * [Setup Card Manager][_card_manager] to manage user's Public Keys
  * [Setup Card Verifier][_card_verifier] to verify signatures inside of user's Card
  * [Setup Key storage][_key_storage] to store Private Keys
* [More usage examples][_more_examples]
  * [Create & publish a Card][_create_card] that has a Public Key on Virgil Cards Service
  * [Search user's Card by user's identity][_search_card]
  * [Get user's Card by its ID][_get_card]
  * [Use Card for crypto operations][_use_card]
* [Reference API][_reference_api]

## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support

Our developer support team is here to help you.

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://join.slack.com/t/VirgilSecurity/shared_invite/enQtMjg4MDE4ODM3ODA4LTc2OWQwOTQ3YjNhNTQ0ZjJiZDc2NjkzYjYxNTI0YzhmNTY2ZDliMGJjYWQ5YmZiOGU5ZWEzNmJiMWZhYWVmYTM).


[_virgil_crypto]: https://github.com/VirgilSecurity/virgil-sdk-crypto-net
[_cards_service]: https://developer.virgilsecurity.com/docs/api-reference/card-service/v4
[_use_card]: https://developer.virgilsecurity.com/docs/python/how-to/public-key-management/v4/use-card-for-crypto-operation
[_get_card]: https://developer.virgilsecurity.com/docs/python/how-to/public-key-management/v4/get-card
[_search_card]: https://developer.virgilsecurity.com/docs/python/how-to/public-key-management/v4/search-card
[_create_card]: https://developer.virgilsecurity.com/docs/python/how-to/public-key-management/v4/create-card
[_key_storage]: https://developer.virgilsecurity.com/docs/python/how-to/setup/v4/setup-key-storage
[_card_verifier]: https://developer.virgilsecurity.com/docs/python/how-to/setup/v4/setup-card-verifier
[_card_manager]: https://developer.virgilsecurity.com/docs/python/how-to/setup/v4/setup-card-manager
[_setup_authentication]: https://developer.virgilsecurity.com/docs/python/how-to/setup/v4/setup-authentication
[_services_reference_api]: https://developer.virgilsecurity.com/docs/api-reference
[_configure_sdk]: https://developer.virgilsecurity.com/docs/how-to#sdk-configuration
[_more_examples]: https://developer.virgilsecurity.com/docs/how-to#public-key-management
[_reference_api]: https://virgilsecurity.github.io/virgil-sdk-python
