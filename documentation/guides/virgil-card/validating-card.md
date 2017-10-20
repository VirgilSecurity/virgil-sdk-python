# Validating Cards

This guide shows how to validate a **Virgil Card** on a device. As previously noted, each Virgil Card contains a Digital signature that provides data integrity for the Virgil Card over its life cycle. Therefore, developers can verify the Digital Signature at any time.

During the validation process we verify, by default, two signatures:
- **from Virgil Card owner**
- **from Virgil Services**

Additionally, developers can verify the **signature of the application server**.

Set up your project environment before you begin to validate a Virgil Card, with the [getting started](https://github.com/VirgilSecurity/virgil-sdk-python/blob/docs-review/documentation/guides/configuration/client-configuration.md) guide.

In order to validate the signature of the Virgil Card owner, **Virgil Services**, and the Application Server, we need to:

```python
app_public_key = VirgilBuffer.from_string("[YOUR_APP_PUBLIC_KEY_HERE]", "base64")

# initialize High Level Api with custom verifiers
virgil = Virgil(
    context=VirgilContext(
        access_token="[YOUR_ACCESS_TOKEN_HERE]",
        card_verifiers=CardVerifierInfo(
            card_id="[YOUR_APP_CARD_ID_HERE]",
            public_key=app_public_key
        )
    )
)
