# Virgil Security Python SDK
[![PyPI](https://img.shields.io/pypi/v/virgil-sdk.svg)](https://pypi.python.org/pypi/virgil-sdk) [![PyPI](https://img.shields.io/pypi/wheel/virgil-sdk.svg)](https://pypi.python.org/pypi/virgil-sdk) [![PyPI](https://img.shields.io/pypi/pyversions/virgil-sdk.svg)](https://pypi.python.org/pypi/virgil-sdk)

[Installation](#installation) | [Initialization](#initialization) | [Encryption / Decryption Example](#encryption-example) |  [Documentation](#documentation) | [Support](#support)

[Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application. In a few steps, you can encrypt communication, securely store data, provide passwordless authentication, and ensure data integrity.

To initialize and use Virgil SDK, you need to have [Developer Account](https://developer.virgilsecurity.com/account/signin).

## Installation

The Virgil Python SDK is provided as a package named *virgil-sdk*. The package is distributed via Pypi package management system.

To install the pip package use the command below:
```bash
pip install virgil-sdk
```


## Initialization

Be sure that you have already registered at the [Dev Portal](https://developer.virgilsecurity.com/account/signin) and created your application.

To initialize the SDK at the __Client Side__ you need only the __Access Token__ created for a client at [Dev Portal](https://developer.virgilsecurity.com/account/signin). The Access Token helps to authenticate client's requests.

```python
virgil = Virgil("[ACCESS_TOKEN]")
```



To initialize the SDK at the __Server Side__ you need the application credentials (__Access Token__, __App ID__, __App Key__ and __App Key Password__) you got during Application registration at the [Dev Portal](https://developer.virgilsecurity.com/account/signin).

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



## Encryption / Decryption Example

Virgil Security simplifies adding encryption to any application. With our SDK you may create unique Virgil Cards for your all users and devices. With users' Virgil Cards, you can easily encrypt any data at Client Side.

```python
# find Alice's card(s) at Virgil Services
alice_card = virgil.cards.find("alice")

# encrypt the message using Alice's Virgil cards
message = "Hello Alice!"
encrypted_message = alice_cards.encrypt(message)

# transmit the message with your preferred technology to Alice
transmit_message(encrypted_message.to_string("base64"))
```

Alice uses her Virgil Private Key to decrypt the encrypted message.


```python
# load Alice's Key from local storage.
alice_key = virgil.keys.load("alice_key_1", "mypassword")

# decrypt the message using the Alice Virgil key
original_message = alice_key.decrypt(transfer_data).to_string()
```

__Next:__ On the page below you can find configuration documentation and the list of our guides and use cases where you can see appliance of Virgil Python SDK.


## Documentation

Virgil Security has a powerful set of APIs and the documentation to help you get started:

* [Get Started](/documentation/get-started) documentation
  * [Encrypted storage](/documentation/get-started/encrypted-storage.md)
  * [Encrypted communication](/documentation/get-started/encrypted-communication.md)
  * [Data integrity](/documentation/get-started/data-integrity.md)
* [Guides](/documentation/guides)
  * [Virgil Cards](/documentation/guides/virgil-card)
  * [Virgil Keys](/documentation/guides/virgil-key)
  * [Encryption](/documentation/guides/encryption)
  * [Signature](/documentation/guides/signature)
* [Configuration](/documentation/guides/configuration)
  * [Set Up Client Side](/documentation/guides/configuration/client.md)
  * [Set Up Server Side](/documentation/guides/configuration/server.md)

## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support

Our developer support team is here to help you. You can find us on [Twitter](https://twitter.com/virgilsecurity) and [email][support].

[support]: mailto:support@virgilsecurity.com
