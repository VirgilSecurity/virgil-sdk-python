# Virgil Security Python SDK 
[![PyPI](https://img.shields.io/pypi/v/virgil-sdk.svg)](https://pypi.python.org/pypi/virgil-sdk) [![PyPI](https://img.shields.io/pypi/wheel/virgil-sdk.svg)](https://pypi.python.org/pypi/virgil-sdk) [![PyPI](https://img.shields.io/pypi/pyversions/virgil-sdk.svg)](https://pypi.python.org/pypi/virgil-sdk)

[Installation](#installation) | [Encryption Example](#encryption-example) | [Initialization](#initialization) | [Documentation](#documentation) | [Reference API][_reference_api] | [Support](#support)

[Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application. In a few simple steps you can encrypt communication, securely store data, provide passwordless login, and ensure data integrity.

For a full overview head over to our Python [Get Started][_getstarted] guides.

## Installation

The Virgil Python SDK is provided as a package named *virgil-sdk*. The package is distributed via Pypi package management system.
To install the pip package use the command below:
```bash
pip install virgil-sdk
```

__Next:__ [Get Started with the Python SDK][_getstarted].

## Encryption Example

Virgil Security makes it super easy to add encryption to any application. With our SDK you create a public [__Virgil Card__][_guide_virgil_cards] for every one of your users and devices. With these in place you can easily encrypt any data in the client.

```python
# find Alice's card(s)
alice_card = virgil.cards.find("alice")

# encrypt the message using Alice's cards
message = "Hello Alice!"
encrypted_message = alice_cards.encrypt(message)

# transmit the message with your preferred technology
transmit_message(encrypted_message.to_string("base64"))
```

The receiving user then uses their stored __private key__ to decrypt the message.


```python
# load Alice's Key from storage.
alice_key = virgil.keys.load("alice_key_1", "mypassword")

# decrypt the message using the key 
original_message = alice_key.decrypt(transfer_data).to_string()
```

__Next:__ To [get you properly started][_guide_encryption] you'll need to know how to create and store Virgil Cards. Our [Get Started guide][_guide_encryption] will get you there all the way.

__Also:__ [Encrypted communication][_getstarted_encryption] is just one of the few things our SDK can do. Have a look at our guides on  [Encrypted Storage][_getstarted_storage], [Data Integrity][_getstarted_data_integrity] and [Passwordless Login][_getstarted_passwordless_login] for more information.

## Initialization

To use this SDK you need to [sign up for an account](https://developer.virgilsecurity.com/account/signup) and create your first __application__. Make sure to save the __app id__, __private key__ and it's __password__. After this, create an __application token__ for your application to make authenticated requests from your clients.

To initialize the SDK on the client side you will only need the __access token__ you created.

```python
virgil = Virgil("[ACCESS_TOKEN]")
```

> __Note:__ this client will have limited capabilities. For example, it will be able to generate new __Cards__ but it will need a server-side client to transmit these to Virgil.

To initialize the SDK on the server side we will need the __access token__, __app id__ and the __App Key__ you created on the [Developer Dashboard](https://developer.virgilsecurity.com/account/dashboard).

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

Next: [Learn more about our the different ways of initializing the Python SDK][_guide_initialization] in our documentation.

## Documentation

Virgil Security has a powerful set of APIs, and the documentation is there to get you started today.

* [Get Started][_getstarted_root] documentation
  * [Initialize the SDK][_initialize_root]
  * [Encrypted storage][_getstarted_storage]
  * [Encrypted communication][_getstarted_encryption]
  * [Data integrity][_getstarted_data_integrity]
  * [Passwordless login][_getstarted_passwordless_login]
* [Guides][_guides]
  * [Virgil Cards][_guide_virgil_cards]
  * [Virgil Keys][_guide_virgil_keys]
* [Reference API][_reference_api]

## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support

Our developer support team is here to help you. You can find us on [Twitter](https://twitter.com/virgilsecurity) and [email](support).

[support]: mailto:support@virgilsecurity.com
[_getstarted_root]: https://developer.virgilsecurity.com/docs/python/get-started
[_getstarted]: https://developer.virgilsecurity.com/docs/python/guides
[_getstarted_encryption]: https://developer.virgilsecurity.com/docs/python/get-started/encrypted-communication
[_getstarted_storage]: https://developer.virgilsecurity.com/docs/python/get-started/encrypted-storage
[_getstarted_data_integrity]: https://developer.virgilsecurity.com/docs/python/get-started/data-integrity
[_getstarted_passwordless_login]: https://developer.virgilsecurity.com/docs/python/get-started/passwordless-authentication
[_guides]: https://developer.virgilsecurity.com/docs/python/guides
[_guide_initialization]: https://developer.virgilsecurity.com/docs/python/guides/settings/install-sdk
[_guide_virgil_cards]: https://developer.virgilsecurity.com/docs/python/guides/virgil-card/creating
[_guide_virgil_keys]: https://developer.virgilsecurity.com/docs/python/guides/virgil-key/generating
[_guide_encryption]: https://developer.virgilsecurity.com/docs/python/guides/encryption/encrypting
[_initialize_root]: https://developer.virgilsecurity.com/docs/python/guides/settings/initialize-sdk-on-client
[_reference_api]: https://virgilsecurity.github.io/virgil-sdk-python
