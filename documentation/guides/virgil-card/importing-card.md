# Importing Card

This guide shows how to import a **Virgil Card** from the string representation.

Set up your project environment before you begin to import a Virgil Card, with the [getting started](https://github.com/VirgilSecurity/virgil-sdk-python/blob/docs-review/documentation/guides/configuration/client-configuration.md) guide.


In order to import the Virgil Card, we need to:

- Initialize the **Virgil SDK**

```python
virgil = Virgil("[YOUR_ACCESS_TOKEN_HERE]")
```

- Use the code below to import the Virgil Card from its string representation

```python
# import a Virgil Card from string
alice_card = virgil.cards.import_card(exported_alice_card)
```
