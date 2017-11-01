# Exporting Virgil Key

This guide shows how to export a **Virgil Key** to the string representation.

Set up your project environment before you begin to export a Virgil Key, with the [getting started](/documentation/guides/configuration/client.md) guide.

In order to export the Virgil Key:

- Initialize **Virgil SDK**

```python
virgil = Virgil("[YOUR_ACCESS_TOKEN_HERE]")
```

- Alice Generates a Virgil Key
- After Virgil Key generated, developers can export Alice's Virgil Key to a Base64 encoded string

```python
# generate a new Virgil Key
alice_key = virgil.keys.generate()

# export the Virgil Key
exported_alice_key = alice_key.export("[OPTIONAL_KEY_PASSWORD]").to_string("base64")
```

Developers also can extract Public Key from a Private Key using the Virgil CLI.
