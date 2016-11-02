# Python SDK Programming Guide

This guide is a practical introduction to creating Python apps using Virgil Security features. The code examples in this guide are written in Python.

In this guide you will find code for every task you need to implement in order to create an application using Virgil Security. It also includes a description of the main classes and methods. The aim of this guide is to get you up and running quickly. You should be able to copy and paste the code provided into your own apps and use it with minumal changes.

## Table of Contents

* [Setting up your project](#setting-up-your-project)
* [User and App Credentials](#user-and-app-credentials)
* [Creating a Virgil Card](#creating-a-virgil-card)
* [Search for Virgil Cards](#search-for-virgil-cards)
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
python -m pip install virgil_sdk
```

## User and App Credentials

When you register an application on the Virgil developer's [dashboard](https://developer.virgilsecurity.com/dashboard), we provide you with an *app_id*, *app_key* and *access_token*.

* **app_id** uniquely identifies your application in our services, it is also used to identify the Public key generated in a pair with *app_key*, for example: ```af6799a2f26376731abb9abf32b5f2ac0933013f42628498adb6b12702df1a87```
* **app_key** is a Private key that is used to perform creation and revocation of *Virgil Cards* (Public key) in Virgil services. Also the *app_key* can be used for cryptographic operations to take part in application logic. The *app_key* is generated at the time of creation application and has to be saved in secure place. 
* **access_token** is a unique string value that provides an authenticated secure access to the Virgil services and is passed with each API call. The *accessToken* also allows the API to associate your app’s requests with your Virgil developer’s account. 

## Connecting to Virgil
Before you can use any Virgil services features in your app, you must first initialize ```VirgilClient``` class from ```virgil_sdk.client``` module. You use the ```VirgilClient``` object to get access to Create, Revoke and Search for *Virgil Cards* (Public keys). 

### Initializing an API Client

To create an instance of *VirgilClient* class, just call its constructor with your application's *access_token* which you generated on developer's deshboard.

Module: ```virgil_sdk.client```

```python
virgil_client = VirgilClient("[YOUR_ACCESS_TOKEN_HERE]")
```

you can also customize initialization using your own parameters

```python
virgil_client = VirgilClient(
    "[YOUR_ACCESS_TOKEN_HERE]",
    cards_service_url="https://cards.virgilsecurity.com",
    cards_read_only_service_url="https://cards-ro.virgilsecurity.com",
)
```

### Initializing Crypto
The *VirgilCrypto* class provides cryptographic operations in applications, such as hashing, signature generation and verification, and encryption and decryption.

Module: ```virgil_sdk.cryptography```

```python
crypto = new VirgilCrypto()
```

## Creating a Virgil Card

A *Virgil Card* is the main entity of the Virgil services, it includes the information about the user and his public key. The *Virgil Card* identifies the user/device by one of his types.

Collect an *app_id* and *app_key* for your app. These parametes are required to create a Virgil Card in your app scope.

```python
app_id = "[YOUR_APP_ID_HERE]"
app_key_password = "[YOUR_APP_KEY_PASSWORD_HERE]"
app_key_data = crypto.strtobytes(open("[YOUR_APP_KEY_PATH_HERE]", "r").read())

app_key = crypto.import_private_key(app_key_data, app_key_password)
```
Generate a new Public/Private keypair using *VirgilCrypto* class.

```python
alice_keys = crypto.generate_keys()
```

Prepare request
```python
exported_public_key = crypto.export_public_key(alice_keys.public_key)
create_card_request = client.requests.CreateCardRequest("alice", "username", exported_public_key)
```

then, use *RequestSigner* class to sign request with owner and app keys.

```python
request_signer = client.RequestSigner(crypto)

request_signer.self_sign(create_card_request, alice_keys.private_key)
requestSigner.authority_sign(create_card_request, app_id, app_key)
```
Publish a Virgil Card
```python
alice_card = virgil_client.create_card_from_signed_request(create_card_request)
```
Or you can use the shorthand versions
```python
alice_keys = crypto.generate_keys()
alice_card = virgil_client.create_card(
    identity="alice",
    identity_type="username",
    key_pair=alice_keys,
    app_id=app_id,
    app_key=app_key
)
```
this will sign and send the card creation request.
## Search for Virgil Cards
Performs the `Virgil Card`s search by criteria:
- the *identities* request parameter is mandatory;
- the *identity_type* is optional and specifies the *IdentityType* of a `Virgil Card`s to be found;
- the *scope* optional request parameter specifies the scope to perform search on. Either 'global' or 'application'. The default value is 'application';

```python
virgil_client = VirgilClient("[YOUR_ACCESS_TOKEN_HERE]")

criteria = SearchCriteria.by_identities("alice", "bob")
cards = client.search_cards_by_criteria(criteria)
```

Or you can use the shorthand versions
```python
virgil_client = VirgilClient("[YOUR_ACCESS_TOKEN_HERE]")

cards = client.search_cards_by_identities("alice", "bob")
app_bundle_cards = client.seach_cards_by_app_bundle("[APP_BUNDLE]")
```
## Validating Virgil Cards
This sample uses *built-in* ```CardValidator``` to validate cards. By default ```CardValidator``` validates only *Cards Service* signature. 

```python
# Initialize crypto API
crypto = VirgilCrypto()

validator = CardValidator(crypto)

# Your can also add another Public Key for verification.
# validator.add_verifier("[HERE_VERIFIER_CARD_ID]", [HERE_VERIFIER_PUBLIC_KEY]);

# Initialize service client
virgil_client = VirgilClient("[YOUR_ACCESS_TOKEN_HERE]")
virgil_client.set_card_validator(validator)

try:
    cards = virgil_client.search_cards_by_identities("alice", "bob");
except CardValidationException as ex:
    # ex.invalid_cards is the list of Card objects that didn't pass validation
```

## Revoking a Virgil Card
Initialize required components.
```python
virgil_client = new VirgilClient("[YOUR_ACCESS_TOKEN_HERE]")
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

Prepare revocation request
```python
card_id = "[YOUR_CARD_ID_HERE]"

revoke_request = RevokeCardRequest(card_id, RevokeCardRequest.Reasons.Unspecified)
request_signer.authority_sign(revoke_request, app_id, app_key)

client.revoke_card_from_signed_request(revoke_request);
```
The shorthand version is
```python
virgil_client.revoke_card(
    card_id="[YOUR_CARD_ID_HERE]",
    reason=RevokeCardRequest.Reasons.Unspecified,
    app_id=app_id,
    app_key=app_key
)
```
## Operations with Crypto Keys

### Generate Keys
The following code sample illustrates keypair generation. The default algorithm is ed25519

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

To import Public/Private keys, simply call one of the Import methods:

```python
private_key = crypto.import_private_key(exported_private_key)
public_key = crypto.import_public_key(exported_public_key)
```

## Encryption and Decryption

Initialize Crypto API and generate keypair.
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
crypto = new VirgilCrypto()
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
```python
cipher_data = crypto.sign_then_encrypt(
  data,
  alice.private_key,
  bob.public_key
)
```

### Decrypt then Verify
```csharp
decrypted_data = crypto.decrypt_then_verify(
  cipher_data,
  bob.private_key,
  alice.public_key
)
```

## Fingerprint Generation
The default Fingerprint algorithm is SHA-256.
```python
crypto = new VirgilCrypto()
fingerprint = crypto.calculate_fingerprint(content_bytes)
```

## Release Notes
 - Please read the latest note here: [https://github.com/VirgilSecurity/virgil-sdk-python/releases](https://github.com/VirgilSecurity/virgil-sdk-python/releases)
