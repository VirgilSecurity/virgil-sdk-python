# Virgil Security Python SDK
[![PyPI](https://img.shields.io/pypi/v/virgil-sdk.svg)](https://pypi.python.org/pypi/virgil-sdk) [![PyPI](https://img.shields.io/pypi/wheel/virgil-sdk.svg)](https://pypi.python.org/pypi/virgil-sdk) [![PyPI](https://img.shields.io/pypi/pyversions/virgil-sdk.svg)](https://pypi.python.org/pypi/virgil-sdk)

[Introduction](#introduction) | [SDK Features](#sdk-features) | [Installation](#installation) | [Initialization](#initialization) | [Usage Examples](#usage-examples) | [Docs](#docs) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a> [Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application. In a few simple steps you can encrypt communication, securely store data, provide passwordless login, and ensure data integrity.


The Virgil SDK allows developers to get up and running with Virgil API quickly and add full end-to-end security to their existing digital solutions to become HIPAA and GDPR compliant and more.

## Installation

The Virgil Python SDK is provided as a package named *virgil_sdk*. The package is distributed via Pypi package management system. The package is available for:
- Python 2.7.x
- Python 3.x


To install the pip package use the command below:

```bash
pip install virgil_sdk
```

## Usage Examples

Before start practicing with the usage examples be sure that the SDK is configured. Check out our [SDK configuration guides][_configure_sdk] for more information.


#### Generate and publish user's Cards with Public Keys inside on Cards Service
Use the following lines of code to create and publish a user's Card with Public Key inside on Virgil Cards Service:


```python
from virgil_crypto import VirgilCrypto
from virgil_sdk.storage import PrivateKeyStorage

crypto = VirgilCrypto()


# generate a key pair
key_pair = crypto.generate_keys()

# save Alice private key into key sotrage
private_key_storage = PrivateKeyStorage()
private_key_storage.store(key_pair.private_key, "Alice")


# create and publish user's card with identity Alice on the Card Service
card = card_manager.publish_card(
    identity="Alice",
    private_key=key_pair.private_key,
    public_key=key_pair.public_key
)
```

#### Sign then encrypt data

Virgil SDK lets you use a user's Private key and his or her Cards to sign, then encrypt any kind of data.

In the following example, we load a Private Key from a customized Key Storage and get recipient's Card from the Virgil Cards Services. Recipient's Card contains a Public Key on which we will encrypt the data and verify a signature.

```python
from virgil_sdk.utils import Utils

# prepare a message
message_to_encrypt = "Hello, Bob!"
data_to_encrypt = Utils.strtobytes(message_to_encrypt)

# load a private key from a device storage
alice_private_key, alice_private_key_additional_data = private_key_storage.load("Alice")

# using CardManager search for Bob's cards on Cards Service
cards = card_manager.search_card("Bob")
bob_relevant_public_keys = list(map(lambda x: x.public_key, cards))

# sign a message with a private key then encrypt using Bob's public keys
encrypted_data = crypto.sign_then_encrypt(data_to_encrypt, alice_private_key, bob_relevant_public_keys)

```

#### Decrypt then verify data
Once the Users receive the signed and encrypted message, they can decrypt it with their own Private Key and verify signature with a Sender's Card:


```python
# load private key from device storage
bob_private_key, bob_private_key_additional_data = private_key_storage.load("Bob")

# using CardManager search for Alice's cards on Cards Service
cards = card_manager.search_card("Alice")
alice_relevant_public_keys = list(map(lambda x: x.public_key, cards))

# decrypt with a private key and verify using one of Alice's public keys
decrypted_data = crypto.decrypt_then_verify(encrypted_data, bob_private_key, alice_relevant_public_keys)
```


## Docs
Virgil Security has a powerful set of APIs, and the documentation below can get you started today.

In order to use the Virgil SDK with your application, you will need to first configure your application. By default, the SDK will attempt to look for Virgil-specific settings in your application but you can change it during SDK configuration.

* [Configure the SDK][_configure_sdk] documentation
  * [Setup authentication][_setup_authentication] to make API calls to Virgil Services
  * [Setup Card Manager][_card_manager] to manage user's Public Keys
  * [Setup Card Verifier][_card_verifier] to verify signatures inside of user's Card
  * [Setup Key storage][_key_storage] to store Private Keys

  * [Setup your own Crypto library][_own_crypto] inside of the SDK
* [More usage examples][_more_examples]
  * [Create & publish a Card][_create_card] that has a Public Key on Virgil Cards Service
  * [Search user's Card by user's identity][_search_card]
  * [Get user's Card by its ID][_get_card]
  * [Use Card for crypto operations][_use_card]
* [Reference API][_reference_api]


## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.slack.com/join/shared_invite/enQtMjg4MDE4ODM3ODA4LTc2OWQwOTQ3YjNhNTQ0ZjJiZDc2NjkzYjYxNTI0YzhmNTY2ZDliMGJjYWQ5YmZiOGU5ZWEzNmJiMWZhYWVmYTM).


[_virgil_crypto]: https://github.com/VirgilSecurity/virgil-sdk-crypto-net
[_cards_service]: https://developer.virgilsecurity.com/docs/api-reference/card-service/v5
[_use_card]: https://developer.virgilsecurity.com/docs/cs/how-to/public-key-management/v5/use-card-for-crypto-operation
[_get_card]: https://developer.virgilsecurity.com/docs/cs/how-to/public-key-management/v5/get-card
[_search_card]: https://developer.virgilsecurity.com/docs/cs/how-to/public-key-management/v5/search-card
[_create_card]: https://developer.virgilsecurity.com/docs/cs/how-to/public-key-management/v5/create-card
[_own_crypto]: https://developer.virgilsecurity.com/docs/cs/how-to/setup/v5/setup-own-crypto-library
[_key_storage]: https://developer.virgilsecurity.com/docs/cs/how-to/setup/v5/setup-key-storage
[_card_verifier]: https://developer.virgilsecurity.com/docs/cs/how-to/setup/v5/setup-card-verifier
[_card_manager]: https://developer.virgilsecurity.com/docs/cs/how-to/setup/v5/setup-card-manager
[_setup_authentication]: https://developer.virgilsecurity.com/docs/cs/how-to/setup/v5/setup-authentication
[_reference_api]: https://developer.virgilsecurity.com/docs/api-reference
[_configure_sdk]: https://developer.virgilsecurity.com/docs/how-to#sdk-configuration
[_more_examples]: https://developer.virgilsecurity.com/docs/how-to#public-key-management