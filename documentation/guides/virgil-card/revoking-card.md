# Revoking Card

This guide shows how to revoke a **Virgil Card** from Virgil Services.

Set up your project environment before you begin to revoke a Virgil Card, with the [getting started](/documentation/guides/configuration/client.md) guide.

In order to revoke a Virgil Card, we need to:

- Initialize the **Virgil SDK** and enter Application **credentials** (**App ID**, **App Key**, **App Key password**)

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

- Get Alice's Virgil Card by **ID** from **Virgil Services**
- Revoke Alice's Virgil Card from Virgil Services

```python
# get a Virgil Card by ID
alice_card = virgil.cards.get("[USER_CARD_ID_HERE]")

# revoke a Virgil Card
virgil.cards.revoke(alice_card)
```
