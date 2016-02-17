# Quickstart Python

- [Introduction](#introduction)
- [Obtaining an Access Token](#obtaining-an-access-token)
- [Install](#install)
- [Use case](#use-case)
    - [Initialization](#initialization)
    - [Step 1. Create and Publish the Keys](#step-1-create-and-publish-the-keys)
    - [Step 2. Encrypt and Sign](#step-2-encrypt-and-sign)
    - [Step 3. Send an Email](#step-3-send-an-email)
    - [Step 4. Receive an Email](#step-4-receive-an-email)
    - [Step 5. Get sender's Public Key](#step-5-get-senders-public-key)
    - [Step 6. Verify and Decrypt](#step-6-verify-and-decrypt)
- [See also](#see-also)

## Introduction

This guide will help you get started using the Crypto Library and Virgil Keys Services for the most popular platforms and languages.
This branch focuses on the C#/.NET library implementation and covers it's usage.

Let's build an encrypted mail exchange system as one of the possible [use cases](#use-case) of Virgil Security Services. ![Use case mail](https://raw.githubusercontent.com/VirgilSecurity/virgil/master/images/Email-diagram.jpg)

## Obtaining an Access Token

First you must create a free Virgil Security developer's account by signing up [here](https://developer.virgilsecurity.com/account/signup). Once you have your account you can [sign in](https://developer.virgilsecurity.com/account/signin) and generate an access token for your application.

The access token provides authenticated secure access to Virgil Keys Services and is passed with each API call. The access token also allows the API to associate your appвЂ™s requests with your Virgil Security developer's account.

Use this token to initialize the SDK client [here](#initialization).

## Install

To install package use command below:

```
command line> python setup.py install
```

You can easily add SDK dependency to your project, just add following code:

```python
from VirgilSDK import virgilhub
import VirgilSDK.virgil_crypto.cryptolib as cryptolib
```

## Use Case
**Secure data at transport**: users need to exchange important data (text, audio, video, etc.) without any risks. 

- Sender and recipient create Virgil accounts with a pair of asymmetric keys:
    - public key on Virgil Public Keys Service;
    - private key on Virgil Private Keys Service or locally.
- Sender encrypts the data using Virgil Crypto Library and the recipientвЂ™s public key.
- Sender signs the encrypted data with his private key using Virgil Crypto Library.
- Sender securely transfers the encrypted data, his digital signature and UDID to the recipient without any risk to be revealed.
- Recipient verifies that the signature of transferred data is valid using the signature and senderвЂ™s public key in Virgil Crypto Library.
- Recipient decrypts the data with his private key using Virgil Crypto Library.
- Decrypted data is provided to the recipient.

## Initialization

```python
identity_link = '%IDENTITY_SERVICE_URL%'
virgil_card_link = '%VIRGIL_CARD_SERVICE_URL%'
private_key_link = '%PRIVATE_KEY_SERVICE_URL%'
virgil_hub = virgilhub.VirgilHub('%ACCESS_TOKEN%', identity_link, virgil_card_link, private_key_link)
```

## Step 1. Create and Publish the Keys
First we are generating the keys and publishing them to the Public Keys Service where they are available in an open access for other users (e.g. recipient) to verify and encrypt the data for the key owner.

The following code example creates a new public/private key pair.

```python
keys = cryptolib.CryptoWrapper.generate_keys(cryptolib.crypto_helper.VirgilKeyPair.Type_EC_SECP521R1, '%PASSWORD%') 
```

We are verifying whether the user really owns the provided email address and getting a temporary token for public key registration on the Public Keys Service.

```python
verifyResponse = virgil_hub.identity.verify('email', 'sender-test@virgilsecurity.com')
# use confirmation code sent to your email box.
identResponse = virgil_hub.identity.confirm('%CONFIRMATION_CODE%', verifyResponse['action_id'])
```
We are registering a Virgil Card which includes a public key and an email address identifier. The card will be used for the public key identification and searching for it in the Public Keys Service.

```python
data ={'Field1': 'Data1', 'Field2': 'Data2'}
new_card = virgil_hub.virgilcard.create_card('email', 'sender-test@virgilsecurity.com', data, identResponse['validation_token'],
                                             keys['private_key'], '%PASSWORD%', keys['public_key'])
```

## Step 2. Encrypt and Sign
We are searching for the recipient's public key on the Public Keys Service to encrypt a message for him. And we are signing the encrypted message with our private key so that the recipient can make sure the message had been sent from the declared sender.

```python
message = "Encrypt me, Please!!!";
recipient_cards = virgil_hub.virgilcard.search_card('recipient-test@virgilsecurity.com')
for card in recipient_cards:
  encrypted_message = cryptolib.CryptoWrapper.encrypt(message, card['id'], 
                                                            base64.b64decode(card['public_key']['public_key']))
  crypto_signature = cryptolib.CryptoWrapper.sign(message, keys['private_key'], '%PASSWORD%')
```

## Step 3. Send an Email
We are merging the message and the signature into one structure and sending the letter to the recipient using a simple mail client.

```python
encryptedBody = {
    'Content' = encrypted_messages,
    'Signature' = crypto_signature
}
encryptedBodyJson = json.dumps(encryptedBody)
mailClient.Send("recipient-test@virgilsecurity.com", "Secure the Future", encryptedBodyJson)
```

## Step 4. Receive an Email
An encrypted letter is received on the recipient's side using a simple mail client.

```python
// get first email with specified subject using simple mail client
var email = mailClient.GetBySubject("recipient-test@virgilsecurity.com", "Secure the Future")
var encryptedBody = json.loads(email.Body)
```

## Step 5. Get sender's Public Key
In order to decrypt the received data the app on recipientвЂ™s side needs to get senderвЂ™s Virgil Card from the Public Keys Service.

```python
senderCard = virgil_hub.virgilcard.search_card(value, 'email')
```

## Step 6. Verify and Decrypt
We are making sure the letter came from the declared sender by getting his card on Public Keys Service. In case of success we are decrypting the letter using the recipient's private key.

```python
is_valid = cryptolib.CryptoWrapper.verify(encryptedBody['Content'], encryptedBody['Signature'],                               base64.b64decode(senderCard['public_key']['public_key']))
if !is_valid:
    raise ValueError("Signature is not valid.")

data = cryptolib.CryptoWrapper.decrypt(encryptedBody['Content'], '%RECIPIENT_ID%', recipientKeyPair['private_key'], '%PASSWORD%')
```

