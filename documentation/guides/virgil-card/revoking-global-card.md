# Revoking Global Card

This guide shows how to revoke a **Global Virgil Card**.

Set up your project environment before you begin to revoke a Global Virgil Card, with the [getting started](https://github.com/VirgilSecurity/virgil-sdk-python/blob/docs-review/documentation/guides/configuration/client-configuration.md) guide.

In order to revoke a Global Virgil Card, we need to:

-  Initialize the Virgil SDK

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

- Load Alice's **Virgil Key** from the secure storage provided by default
- Load Alice's Virgil Card from **Virgil Services**
- Initiate the Card's identity verification process
- Confirm the Card's identity using a **confirmation code**
- Revoke the Global Virgil Card from Virgil Services

```python
# load a Virgil Key from storage
alice_key = virgil.keys.load("[KEY_NAME]", "[OPTIONAL_KEY_PASSWORD]")

# load a Virgil Card from Virgil Services
alice_card = virgil.cards.get("[USER_CARD_ID_HERE]")

# create identity
identity = virgil.identities.create_email(alice_card.identity)

# initiate an identity verification process.
identity.check()

# confirm your identity
identity.confirm("[CONFIRMATION_CODE]")

# revoke a Global Virgil Card
virgil.cards.revoke_global(alice_card, alice_key, identity)
```
