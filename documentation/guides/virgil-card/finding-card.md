# Finding Card

This guide shows how to find a **Virgil Card**. As previously noted, all Virgil Cards are saved at **Virgil Services** after their publication. Thus, every user can find their own Virgil Card or another user's Virgil Card on Virgil Services. It should be noted that users' Virgil Cards will only be visible to application users. Global Virgil Cards will be visible to anybody.

Set up your project environment before you begin to find a Virgil Card, with the [getting started](/documentation/guides/configuration/client.md) guide.


In order to search for an **Application** or **Global Virgil Card** you need to initialize the **Virgil SDK**:

```python
virgil = Virgil("[YOUR_ACCESS_TOKEN_HERE]")
```

### Application Cards

There are two ways to find an Application Virgil Card on Virgil Services:

The first one allows developers to get the Virgil Card by its unique **ID**

```python
alice_card = virgil.cards.get("[ALICE_CARD_ID]")
```

The second one allows developers to find Virgil Cards by *identity* and *identityType*

```python
# search for all User's Virgil Cards.
alice_cards = virgil.cards.find(["alice"])

# search for all User's Virgil Cards with identity type 'member'
bobCards = virgil.cards.find("bob", "member")
```

### Global Cards

```python
# search for all Global Virgil Cards
list_for_search = ["bob@virgilsecurity.com"]
bob_global_cards = virgil.cards.find_global(list_for_search)

# search for Application Virgil Card
app_cards = virgil.cards.find_global("com.username.appname")
```
