# Virgil Core SDK Python
[![Travis (.com)](https://img.shields.io/travis/com/VirgilSecurity/virgil-sdk-python/master.svg)](https://travis-ci.com/VirgilSecurity/virgil-sdk-python) [![PyPI](https://img.shields.io/pypi/v/virgil-sdk.svg)](https://pypi.python.org/pypi/virgil-sdk) [![PyPI](https://img.shields.io/pypi/wheel/virgil-sdk.svg)](https://pypi.python.org/pypi/virgil-sdk) [![PyPI](https://img.shields.io/pypi/pyversions/virgil-sdk.svg)](https://pypi.python.org/pypi/virgil-sdk)

[Introduction](#introduction) | [SDK Features](#sdk-features) | [Crypto Library Purposes](#crypto-library-purposes) | [Installation](#installation) | [Configure SDK](#configure-sdk) | [Sample Backend for JWT Generation](#sample-backend-for-jwt-generation) | [Usage Examples](#usage-examples) | [Docs](#docs) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a> [Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application. In a few simple steps you can encrypt communications, securely store data, and ensure data integrity. Virgil Security products are available for desktop, embedded (IoT), mobile, cloud, and web applications in a variety of modern programming languages.

The Virgil Core SDK is a low-level library that allows developers to get up and running with [Virgil Cards Service API](https://developer.virgilsecurity.com/docs/platform/api-reference/cards-service/) quickly and add end-to-end security to their new or existing digital solutions.

In case you need additional security functionality for multi-device support, group chats and more, try our high-level [Virgil E3Kit framework](https://github.com/VirgilSecurity/awesome-virgil#E3Kit).

## SDK Features
- Communicate with [Virgil Cards Service](https://developer.virgilsecurity.com/docs/platform/api-reference/cards-service/)
- Manage users' public keys
- Encrypt, sign, decrypt and verify data
- Store private keys in secure local storage
- Use [Virgil Crypto Library](https://github.com/VirgilSecurity/virgil-crypto-python)
- Use your own crypto library

## Installation

The Virgil Core SDK Python is provided as a package named *virgil_sdk*. The package is distributed via Pypi package management system. The package is available for:
- Python 2.7.x
- Python 3.x


To install the pip package use the command below:

```bash
pip install virgil-sdk
```


## Configure SDK

This section contains guides on how to set up Virgil Core SDK modules for authenticating users, managing Virgil Cards and storing private keys.

### Set up authentication

Set up user authentication with tokens that are based on the [JSON Web Token standard](https://jwt.io/) with some Virgil modifications.

In order to make calls to Virgil Services (for example, to publish user's Card on Virgil Cards Service), you need to have a JSON Web Token ("JWT") that contains the user's `identity`, which is a string that uniquely identifies each user in your application.

Credentials that you'll need:

|Parameter|Description|
|--- |--- |
|App ID|ID of your Application at [Virgil Dashboard](https://dashboard.virgilsecurity.com)|
|App Key ID|A unique string value that identifies your account at the Virgil developer portal|
|App Key|A Private Key that is used to sign API calls to Virgil Services. For security, you will only be shown the App Key when the key is created. Don't forget to save it in a secure location for the next step|

#### Set up JWT provider on Client side

Use these lines of code to specify which JWT generation source you prefer to use in your project:

```python
from virgil_sdk.jwt.providers import CallbackJwtProvider

# Get generated token from server-side
def get_token_from_server():
    jwt_from_server = aunthficated_query_to_server(token_context)
    return jwt_from_server

# setup access token
access_token_provider = CallbackJwtProvider(get_token_from_server)
```

#### Generate JWT on Server side

Next, you'll need to set up the `JwtGenerator` and generate a JWT using the Virgil SDK.

Here is an example of how to generate a JWT:

```python
import datetime

from virgil_crypto import VirgilCrypto
from virgil_crypto.access_token_signer import AccessTokenSigner
from virgil_sdk.jwt import JwtGenerator
from virgil_sdk.utils import Utils

# App Key (you got this Key at Virgil Dashboard)
app_key_base64 = "MIGhMF0GCSqGSIb3DQEFDTBQMC8GCSqGS...gRbjAtoWkfWraSLD6gj0="
private_key_data = Utils.b64_decode(app_key_base64)

# Crypto library imports a private key into a necessary format
crypto = VirgilCrypto()
app_key = crypto.import_private_key(private_key_data)

#  initialize accessTokenSigner that signs users JWTs
access_token_signer = AccessTokenSigner()

# use your App Credentials you got at Virgil Dashboard:
app_id = "be00e10e4e1f4bf58f9b4dc85d79c77a"
app_key_id = "70b447e321f3a0fd"
ttl = datetime.timedelta(hours=1).seconds

# setup JWT generator with necessary parameters:
jwt_generator = JwtGenerator(app_id, app_key, app_key_id, ttl, access_token_signer)

# generate JWT for a user
# remember that you must provide each user with his unique JWT
# each JWT contains unique user's identity (in this case - Alice)
# identity can be any value: name, email, some id etc.
identity = "Alice"
alice_jwt = jwt_generator.generate_token(identity)

# as result you get users JWT, it looks like this: "eyJraWQiOiI3MGI0NDdlMzIxZjNhMGZkIiwidHlwIjoiSldUIiwiYWxnIjoiVkVEUzUxMiIsImN0eSI6InZpcmdpbC1qd3Q7dj0xIn0.eyJleHAiOjE1MTg2OTg5MTcsImlzcyI6InZpcmdpbC1iZTAwZTEwZTRlMWY0YmY1OGY5YjRkYzg1ZDc5Yzc3YSIsInN1YiI6ImlkZW50aXR5LUFsaWNlIiwiaWF0IjoxNTE4NjEyNTE3fQ.MFEwDQYJYIZIAWUDBAIDBQAEQP4Yo3yjmt8WWJ5mqs3Yrqc_VzG6nBtrW2KIjP-kxiIJL_7Wv0pqty7PDbDoGhkX8CJa6UOdyn3rBWRvMK7p7Ak"
# you can provide users with JWT at registration or authorization steps
# Send a JWT to client-side
jwt_string = alice_jwt.to_string()
```

For this subsection we've created a sample backend that demonstrates how you can set up your backend to generate the JWTs. To set up and run the sample backend locally, head over to your GitHub repo of choice:

[Node.js](https://github.com/VirgilSecurity/sample-backend-nodejs) | [Golang](https://github.com/VirgilSecurity/sample-backend-go) | [PHP](https://github.com/VirgilSecurity/sample-backend-php) | [Java](https://github.com/VirgilSecurity/sample-backend-java) | [Python](https://github.com/VirgilSecurity/virgil-sdk-python/tree/master#sample-backend-for-jwt-generation)
 and follow the instructions in README.
 
### Set up Card Verifier

Virgil Card Verifier helps you automatically verify signatures of a user's Card, for example when you get a Card from Virgil Cards Service.

By default, `VirgilCardVerifier` verifies only two signatures - those of a Card owner and Virgil Cards Service.

Set up `VirgilCardVerifier` with the following lines of code:

```python
from virgil_crypto.card_crypto import CardCrypto
from virgil_sdk import VirgilCardVerifier
from virgil_sdk.verification import VerifierCredentials, WhiteList

# initialize Crypto library
card_crypto = CardCrypto()
your_backend_verifier_credentials = VerifierCredentials(signer="YOUR_BACKEND", public_key_base64=public_key_str)

your_backend_white_list = WhiteList()
your_backend_white_list.verifiers_credentials = your_backend_verifier_credentials

verifier = VirgilCardVerifier(card_crypto, white_lists=[your_backend_white_list])
```

### Set up Card Manager

This subsection shows how to set up a Card Manager module to help you manage users' public keys.

With Card Manager you can:
- specify an access Token (JWT) Provider.
- specify a Card Verifier used to verify signatures of your users, your App Server, Virgil Services (optional).

Use the following lines of code to set up the Card Manager:

```python
from virgil_sdk import CardManager, VirgilCardVerifier

# initialize card_manager and specify access_token_provider, card_verifier
card_manager = CardManager(
    card_crypto,
    access_token_provider,
    card_verifier
)
```

### Set up Key Storage for private keys

This subsection shows how to set up a `VSSKeyStorage` using Virgil SDK in order to save private keys after their generation.

Here is an example of how to set up the `VSSKeyStorage` class:

```python
from virgil_crypto import VirgilCrypto, PrivateKeyExporter
from virgil_sdk.storage import PrivateKeyStorage

# initialize Crypto library
crypto = VirgilCrypto()

# Generate a private key
key_pair = crypto.generate_keys()
private_key = key_pair.private_key

# Setup PrivateKeyStorage
exporter = PrivateKeyExporter()
private_key_storage = PrivateKeyStorage(exporter, "YOUR_PASSWORD")

# Store a private key with a name, for example Alice
private_key_storage.store(private_key, "Alice")

# To load Alice private key use the following code lines:
loaded_private_key, loaded_additional_data = private_key_storage.load("Alice")

# Delete a private key
private_key_storage.delete("Alice")
```

## Sample Backend for JWT Generation

In order to configure the SDK you can use the sample backend for generating JWT which we created for you.
**JWT** is a unique string that is used by Virgil to authenticate you and users of your application on Virgil Services.

> Do not use this authentication in production. Requests to a /virgil-jwt endpoint must be allowed for authenticated users. Use your application authorization strategy.

### Clone repository

Clone the repository from GitHub.

```
$ git clone https://github.com/VirgilSecurity/virgil-sdk-python.git
```

### Get Virgil credentials

If you don't have an account yet, [sign up for one](https://dashboard.virgilsecurity.com/signup) using your e-mail.

To generate a JWT the following values are required:

| Variable Name                     | Description                    |
|-----------------------------------|--------------------------------|
| API_PRIVATE_KEY                  | Private key of your API key that is used to sign the JWTs. |
| API_KEY_ID               | ID of your API key. A unique string value that identifies your account in the Virgil Cloud. |
| APP_ID                   | ID of your Virgil Application. |

### Add Virgil credentials to sample_backend_for_jwt_generation.py

- navigate to `/examples/sample_backend_for_jwt_generation.py`
- fill it with your account credentials (`# FILL THIS FIELD`)
- save the file

### Run the server

It is required to have Flask installed in order to start the server. In cmd, run the following command:

```
$ pip install Flask
```

Now, start the server:

```
$ cd examples/
$ python sample_backend_for_jwt_generation.py
```

After that use your client code to make a request to get a JWT from the sample backend that is working on http://localhost:5000.

### Specification

#### /authenticate endpoint
This endpoint is an example of users authentication. It takes user `identity` and responds with unique token.

```http
POST https://localhost:5000/authenticate HTTP/1.1
Content-type: application/json;

{
    "identity": "string"
}

Response:

{
    "auth_token": "string"
}
```

#### /virgil-jwt endpoint
This endpoint checks whether a user is authorized by an authorization header. It takes user's `auth_token`, finds related user identity and generates a `virgil_token` (which is [JSON Web Token](https://jwt.io/)) with this `identity` in a payload. Use this token to make authorized api calls to Virgil Cloud.

```http
GET https://localhost:5000/virgil-jwt HTTP/1.1
Content-type: application/json;
Authorization: Bearer <authToken>

Response:

{
    "virgil_token": "string"
}
```

#### Virgil JWT generation
To generate JWT, you need to use the `JwtGenerator` class from the SDK. You can use the `generate_jwt` function from the `sample_backend_for_jwt_generation.py` which will return the JWT with the user's identity.


## Usage Examples

Before you start practicing with the usage examples, make sure that the SDK is configured. See the [Configure SDK](#configure-sdk) section for more information.

### Generate and publish Virgil Cards at Cards Service

Use the following lines of code to create a user's Card with a public key inside and publish it at Virgil Cards Service:

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

### Sign then encrypt data

Virgil Core SDK allows you to use a user's private key and their Virgil Cards to sign and encrypt any kind of data.

In the following example, we load a private key from a customized key storage and get recipient's Card from the Virgil Cards Service. Recipient's Card contains a public key which we will use to encrypt the data and verify a signature.

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

### Decrypt data and verify signature

Once the user receives the signed and encrypted message, they can decrypt it with their own private key and verify the signature with the sender's Card:

```python

# load private key from device storage
bob_private_key, bob_private_key_additional_data = private_key_storage.load("Bob")

# using CardManager search for Alice's cards on Cards Service
cards = card_manager.search_card("Alice")
alice_relevant_public_keys = list(map(lambda x: x.public_key, cards))

# decrypt with a private key and verify using one of Alice's public keys
decrypted_data = crypto.decrypt_then_verify(encrypted_data, bob_private_key, alice_relevant_public_keys)
```

### Get Card by its ID

Use the following lines of code to get a user's card from Virgil Cloud by its ID:

```python

# using CardManager get a user's card from the Cards Service
card = card_manager.get_card("f4bf9f7fcbedaba0392f108c59d8f4a38b3838efb64877380171b54475c2ade8")
```

### Get Card by user's identity

For a single user, use the following lines of code to get a user's Card by a user's `identity`:

```python
# using CardManager search for user's cards on Cards Service
card = card_manager.search_card("Bob")
```

### Encrypt and decrypt large file

If you need to encrypt files larger than 50 MB, we recommend you to take a look at the full code example of how to encrypt and decrypt large files without causing RAM usage overrun [here](/examples/encrypt_decrypt_large_file.py).

## Docs

Virgil Security has a powerful set of APIs, and the [Developer Documentation](https://developer.virgilsecurity.com/) can get you started today.

## License

This library is released under the [3-clause BSD License](LICENSE).

## Support

Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
