# Python SDK Programming Guide

This guide is a practical introduction to creating Python apps using Virgil Security features. The code examples in this guide are written in Python.

In this guide you will find code for every task you need to implement in order to create an application using Virgil Security. It also includes a description of the main classes and methods. The aim of this guide is to get you up and running quickly. You should be able to copy and paste the code provided into your own apps and use it with minumal changes.

## Table of Contents

* [Setting up your project](#setting-up-your-project)
* [User and App Credentials](#user-and-app-credentials)
* [Usage](#usage)
* [Creating a Virgil Card](#creating-a-virgil-card)
* [Search for Virgil Cards](#search-for-virgil-cards)
* [Getting a Virgil Card](#getting-a-virgil-card)
* [Validating Virgil Cards](#validating-virgil-cards)
* [Revoking a Virgil Card](#revoking-a-virgil-card)
* [Operations with Crypto Keys](#operations-with-crypto-keys)
  * [Generate Keys](#generate-keys)
  * [Import and Export Keys](#import-and-export-keys)
* [Encryption and Decryption](#encryption-and-decryption)
  * [Encrypt Data](#encrypt-data)
  * [Decrypt Data](#decrypt-data)
* [Generating and Verifying Signatures](#generating-and-verifying-signatures)
  * [Generating a Signature](#generating-a-signature)
  * [Verifying a Signature](#verifying-a-signature)
* [Authenticated Encryption](#authenticated-encryption)
  * [Sign then Encrypt](#sign-then-encrypt)
  * [Decrypt then Verify](#decrypt-then-verify)
* [Fingerprint Generation](#fingerprint-generation)
* [Release Notes](#release-notes)

## Setting up your project

The Virgil SDK is provided as a package named *virgil-sdk*. The package is distributed via *pip* package manager.

### Target platforms

* Python 2.7+
* Python 3.3+

### Installation

To install package use the command below:

```
python setup.py install
```

or you can use pip to download and install package automatically:

```
python pip install virgil-sdk
```

## User and App Credentials

To start using Virgil Services you first have to create an account at [Virgil 
Developer Portal](https://developer.virgilsecurity.com/account/signup).

After you create an account, or if you already have an account, sign in and 
create a new application. Make sure you save the *private key* that is 
generated for your application at this point as you will need it later. 
After your application is ready, create a *token* that your app will 
use to make authenticated requests to Virgil Services. One more thing that 
you're going to need is your application's *app id* which is an identifier 
of your application's Virgil Card.

## Usage

Now that you have your account and application in place you can start making 
requests to Virgil Services. 


### Initializing an API Client

To initialize the client, you need the *access token* that you created for 
your application on [Virgil Developer Portal](https://developer.virgilsecurity.com/)

Module: ```virgil_sdk.client```

```python
from virgil_sdk.client import VirgilClient

client = VirgilClient("[YOUR_ACCESS_TOKEN_HERE]")
```

### Initializing Crypto
The *VirgilCrypto* class provides cryptographic operations in applications, such as hashing, signature generation and verification, and encryption and decryption.

Module: ```virgil_sdk.cryptography```

```python
from virgil_sdk.cryptography import VirgilCrypto

crypto = VirgilCrypto()
```

## Creating a Virgil Card


At this point you can start creating and publishing *Virgil Cards* for your
users.

> *Virgil Card* is the main entity of Virgil services, it includes the user's 
> identity their public key.

The easiest (and for now the only) way to create a Virgil Card is to create 
it with the `scope` parameter set to `'application'`. The cards created this 
way will only be available to your application (i.e. will only be returned in 
response to a request presenting your application's *access token*).
As your application represents an authority on behalf of which the Virgil 
Cards are created, you're going to need to sign the cards you create with 
your application's private key. You also going to need the *app id* to 
distinguish your app's signature from others. 

```python
app_id = "[YOUR_APP_ID_HERE]"
app_key_password = "[YOUR_APP_KEY_PASSWORD_HERE]"
app_key_data = crypto.strtobytes(open("[YOUR_APP_KEY_PATH_HERE]", "r").read())

app_key = crypto.import_private_key(app_key_data, app_key_password)
```

### Generate a new key pair
 
Virgil Cards include their owner's public key, so the first thing you need 
to create a card is to generate a key pair. Suppose you want to create a card 
for your user whose name is Alice:

```python
alice_keys = crypto.generate_keys()
```


### Prepare request

Next you need a request object that will hold the card's data. The following 
properties are required to create the request:
 
 - **identity** - Identity associated with the card.
 - **identity_type** - The type of identity associated with the card.
 - **public_key** - Public key associated with the Card as a 
 base64-encoded string
 
You may optionally include your application specific parameters to be 
associated with the card via 'data' property, which has to be an associative
list with no more than 16 items, and the length of keys and values must not 
exceed 256 characters.

```python
exported_public_key = crypto.export_public_key(alice_keys.public_key)
create_card_request = client.requests.CreateCardRequest("alice", "username", exported_public_key)
```

### Sign request

When you have the request object ready you need to sign it with two private 
keys: the key of the Card being created and your application's key.

```python
request_signer = client.RequestSigner(crypto)

request_signer.self_sign(create_card_request, alice_keys.private_key)
request_signer.authority_sign(create_card_request, app_id, app_key)
```

### Publish a Virgil Card

After you sign the request object you can send it to Virgil Services to 
conclude the card creation process.
```python
alice_card = client.create_card_from_request(create_card_request)
```

## Search for Virgil Cards

The `client.search_cards_by_criteria` method performs the cards search by criteria. 
It accepts a single `criteria` parameter of `SearchCriteria` class with the following properties:

- **identities** - A list of identity values to search for (Required)
- **identity_type** - Specifies the *identity_type* of the cards to be 
found (Optional).
- **scope** - Specifies the scope to perform search on. Either 'global' or 
'application' (Optional. Default is 'application')

It returns a list of cards matching the criteria once the server response is loaded.
```python
client = VirgilClient("[YOUR_ACCESS_TOKEN_HERE]")

criteria = SearchCriteria.by_identities("alice", "bob")
cards = client.search_cards_by_criteria(criteria)
```

Or you can use the shorthand versions
```python
client = VirgilClient("[YOUR_ACCESS_TOKEN_HERE]")

cards = client.search_cards_by_identities("alice", "bob")
```

## Getting Virgil Cards

In order to encrypt a message for a user you have to know their public key 
(i.e. their Virgil Card). There are two ways you can get cards from Virgil 
Services: search by identity and get by id.

### Get Virgil Card by Id
If you know the id of the card you want to encrypt a message for, you can use 
`client.get_card` method. It accepts a single argument - `card_id` as a string
and returns a card once the it is loaded:

```python
client = VirgilClient("[YOUR_ACCESS_TOKEN_HERE]")
card = client.get_card("[YOUR_CARD_ID_HERE]")
```

## Validating Virgil Cards
You should be verifying the integrity of the cards that you get from the
network. To do that, there is a `CardValidator` class available that you 
use to create a validator object which you can pass to the `client` object 
using its `set_card_validator` method. The client will then check the validity 
of the cards before returning them to the calling code. By default objects 
created by `CardValidator` will check the *Virgil Cards 
Service* signature and the card's owner signature.

```python
# Initialize crypto API
crypto = VirgilCrypto()

validator = CardValidator(crypto)

# Your can also add another Public Key for verification.
# validator.add_verifier("[HERE_VERIFIER_CARD_ID]", [HERE_VERIFIER_PUBLIC_KEY])

# Initialize service client
client = VirgilClient("[YOUR_ACCESS_TOKEN_HERE]")
client.set_card_validator(validator)

try:
    cards = client.search_cards_by_identities("alice", "bob")
except CardValidationException as ex:
    # ex.invalid_cards is the list of Card objects that didn't pass validation
```

## Revoking a Virgil Card

Occasionally you might need to revoke a Virgil Card from the Virgil Services. 
The steps required to do that are similar to those need to publish a card.

Initialize required components.
```python
client = VirgilClient("[YOUR_ACCESS_TOKEN_HERE]")
crypto = VirgilCrypto()
request_signer = RequestSigner(crypto)
```

Collect *App* credentials
```python
app_id = "[YOUR_APP_ID_HERE]"
app_key_password = "[YOUR_APP_KEY_PASSWORD_HERE]"
app_key_data = crypto.strtobytes(open("[YOUR_APP_KEY_PATH_HERE]", "r").read())

app_key = crypto.import_private_key(app_key_data, app_key_password)
```

### Prepare request

To make a request object to revoke a Virgil Card use `RevokeCardRequest`.
It accepts the following properties:
 - **card_id** - Id of card to revoke (Required)
 - **revocation_reason** - The reason for revoking the card. Must be either 
 'unspecified' or 'compromised'. Default is "unspecified". You can use the 
 `RevokeCardRequest.Reasons` enumeration to get the correct value.
 
```python
card_id = "[YOUR_CARD_ID_HERE]"

revoke_request = RevokeCardRequest(card_id, RevokeCardRequest.Reasons.Unspecified)
```

### Sign request

This step is the same as the one for the publish request only this time you 
only have to provide the authority's (i.e. your application's) signature.

```python
request_signer.authority_sign(revoke_request, app_id, app_key)
```

### Send request
```python
client.revoke_card_from_request(revoke_request)
```

## Using Crypto

The `VirgilCrypto` class provides implementation of cryptographic operations 
such as hashing, signature generation and verification as well as encryption 
and decryption. All api functions of `VirgilCrypto` accept byte arrays as base64-encoded strings
and return byte arrays.

## Operations with Crypto Keys

### Generate Keys
The following code sample illustrates key pair generation. The default algorithm is ed25519

```python
alice_keys = crypto.generate_keys()
```

### Import and Export Keys
You can export and import your Public/Private keys to/from supported wire representation.

To export Public/Private keys, simply call one of the Export methods:

```python
exported_private_key = crypto.export_private_key(alice_keys.private_key)
exported_public_key = crypto.export_public_key(alice_keys.public_key)
```

If you want to encrypt the private key before exporting it 
you must provide a password to encrypt the key with as a second parameter to `export_private_key` function.
Similarly, if you want to import a private key
that has been encrypted - provide a password as a second parameter to `import_private_key` function

```python
encrypted_private_key = crypto.export_private_key(alice_keys.private_key, "YOUR_PASSWORD_HERE")
private_key = crypto.import_private_key(exported_private_key, "YOUR_PASSWORD_HERE")

# convert the Private key to base64 encoded string
base64_private_key = base64.b64encode(bytearray(encrypted_private_key))
```

To import Public/Private keys, simply call one of the Import methods:

```python
private_key = crypto.import_private_key(exported_private_key)
public_key = crypto.import_public_key(exported_public_key)
```

## Encryption and Decryption
Data encryption using [ECIES](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme) 
scheme with [AES-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode) mode.

Initialize Crypto API and generate key pair.
```python
crypto = VirgilCrypto()
alice_keys = crypto.generate_keys()
```

### Encrypt Data
Data encryption using ECIES scheme with AES-GCM. You can encrypt either stream or a bytes.
There also can be more than one recipient

*Bytes*
```python
plain_data = crypto.strtobytes("Hello Bob!")
cipher_data = crypto.encrypt(plain_data, alice_keys.public_key)
```

*Stream*
```python
with io.open("[YOUR_FILE_PATH_HERE]", "rb") as input_stream:
    with io.open("[YOUR_ENCRYPTED_FILE_PATH_HERE]", "wb") as output_stream:
        c.encrypt_stream(input_stream, output_stream, [alice_keys.public_key])
```

### Decrypt Data
You can decrypt either stream or a bytes using your private key

*Bytes*
```python
crypto.decrypt(cipher_data, alice_keys.private_key);
```

*Stream*
```python
with io.open("[YOUR_ENCRYPTED_FILE_PATH_HERE]", "rb") as cipher_stream:
    with io.open("[YOUR_DECRYPTED_FILE_PATH_HERE]", "wb") as result_stream:
        c.decrypt_stream(cipher_stream, result_stream, alice_keys.private_key)
```

## Generating and Verifying Signatures
This section walks you through the steps necessary to use the *VirgilCrypto* to generate a digital signature for data and to verify that a signature is authentic. 

Generate a new Public/Private keypair and *data* to be signed.

```python
crypto = VirgilCrypto()
alice_keys = crypto.GenerateKeys()

# The data to be signed with alice's Private key
data = crypto.strtobytes("Hello Bob, How are you?")
```

### Generating a Signature

Sign the SHA-384 fingerprint of either stream or a bytes using your private key. To generate the signature, simply call one of the sign methods:

*Bytes*
```python
signature = crypto.sign(data, alice.private_key)
```
*Stream*
```python
with io.open("[YOUR_FILE_PATH_HERE]", "rb") as input_stream:
    signature = crypto.sign_stream(input_stream, alice.private_key)
```
### Verifying a Signature

Verify the signature of the SHA-384 fingerprint of either stream or a
bytes using Public key. The signature can now be verified by calling the verify method:

*Bytes*

```python
is_valid = crypto.verify(data, signature, alice.public_key)
```

*Stream*

```python
with io.open("[YOUR_FILE_PATH_HERE]", "rb") as input_stream:
    is_valid = crypto.verify_stream(input_stream, signature, alice.public_key)
```

## Authenticated Encryption
Authenticated Encryption provides both data confidentiality and data
integrity assurances to the information being protected.

```python
crypto = VirgilCrypto()

alice = crypto.generate_keys()
bob = crypto.generate_keys()

# The data to be signed with alice's Private key
data = crypto.strtobytes("Hello Bob, How are you?")
```

### Sign then Encrypt

Generates the signature, encrypts the data and attaches the signature to the 
cipher data. Returns a signed cipher data. To encrypt for multiple recipients, 
pass a list of public keys as third parameter

```python
cipher_data = crypto.sign_then_encrypt(
  data,
  alice.private_key,
  bob.public_key
)
```

### Decrypt then Verify
Decrypts the data and verifies attached signature. Returns decrypted data if 
verification succeeded or throws an error if it failed. 

```python
decrypted_data = crypto.decrypt_then_verify(
  cipher_data,
  bob.private_key,
  alice.public_key
)
```

## Fingerprint Generation
The default Fingerprint algorithm is SHA-256.
```python
crypto = VirgilCrypto()
fingerprint = crypto.calculate_fingerprint(content_bytes)
```

## Release Notes
 - Please read the latest note here: [https://github.com/VirgilSecurity/virgil-sdk-python/releases](https://github.com/VirgilSecurity/virgil-sdk-python/releases)
