# Saving Key

This guide shows how to save a **Virgil Key** from the default storage after its [generation](/documentation/guides/virgil-key/generating-key.md).

Before you begin to generate a Virgil Key, Set up your project environment with the [getting started](/documentation/guides/configuration/client.md) guide.

In order to save the Virgil Key we need to:

- Initialize the **Virgil SDK**:

```python
virgil = Virgil("[YOUR_ACCESS_TOKEN_HERE]")
```

- Save Alice's Virgil Key in the protected storage on the device

```python
# save Virgil Key into storage
alice_key.save("[KEY_NAME]", "[OPTIONAL_KEY_PASSWORD]")
```

Developers can also change the Virgil Key storage directory as needed, during Virgil SDK initialization.
