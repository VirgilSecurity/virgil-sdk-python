# Generating Keys

This guide shows how to generate a **Virgil Key**. The Virgil Key is a Private Key, which never leaves its device. Only key holders are allowed to sign and decrypt data. The data was encrypted by Public Key. Every Public Key is associated with particular Private Key.

Before generating a Virgil Key, set up your project environment using the [getting started](https://github.com/VirgilSecurity/virgil-sdk-python/blob/docs-review/documentation/guides/configuration/client-configuration.md) guide.

The Virgil Key generation procedure is shown in the figure below.

![Virgil Key Intro](https://github.com/VirgilSecurity/virgil-sdk-python/blob/docs-review/documentation/img/Key_introduction.png "Keys generation")

There are two options to generate a Virgil Key:
- With **default** key pair type
- With **specific** key pair type


1. To generate a Virgil Key with the **default** type:


- Developers need to initialize the **Virgil SDK**

```python
virgil = Virgil("[YOUR_ACCESS_TOKEN_HERE]")
```

- Then Alice generates a new Virgil Key

```python
# generate a new Virgil Key
alice_key = virgil.keys.generate()
```

**Warning**: Virgil doesn't keep a copy of your Virgil Key. If you lose a Virgil Key, there is no way to recover it.

2. To generate a Virgil Key with a **specific** type, we need to:


- Choose the preferred type and initialize **Virgil Crypto** with this type;
- Initialize the Virgil SDK with a custom Virgil Crypto instance;
- Generate a new Virgil Key.

```python
# initialize Crypto with specific key pair type
crypto = VirgilCrypto()
crypto.key_pair_type = KeyPairType.EC_BP512R1

context = VirgilContext(crypto=crypto)

# initialize Virgil SDK using
virgil = Virgil(context=context)

# generate a new Virgil Key
alice_key = virgil.keys.generate()
```

Developers can also generate a Private Key using the Virgil CLI.
