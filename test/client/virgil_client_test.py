from . import config
from .base_test import BaseTest

from virgil_sdk.client import VirgilClient

class VirgilClientTest(BaseTest):
    def __init__(self, *args, **kwargs):
        super(VirgilClientTest, self).__init__(*args, **kwargs)
        self.__client = None

    def test_create_card_saves_public_key(self):
        alice_keys = self._crypto.generate_keys()
        card = self._client.create_card(
            "alice",
            "username",
            alice_keys,
            config.VIRGIL_APP_ID,
            self._app_private_key,
        )
        self.assertEqual(
            card.identity,
            "alice"
        )
        self.assertEqual(
            card.identity_type,
            "username"
        )
        self.assertEqual(
            card.version,
            "4.0"
        )
        self.assertEqual(
            card.public_key,
            alice_keys.public_key.value,
        )
        self.cleanup_cards(card)

    def test_revoke_card_removes_created_card(self):
        alice_keys = self._crypto.generate_keys()
        card = self._client.create_card(
            "alice",
            "username",
            alice_keys,
            config.VIRGIL_APP_ID,
            self._app_private_key,
        )
        self._client.revoke_card(
            card_id=card.id,
            app_id=config.VIRGIL_APP_ID,
            app_key=self._app_private_key,
        )

    def test_get_card(self):
        alice_keys = self._crypto.generate_keys()
        created_card = self._client.create_card(
            "alice",
            "username",
            alice_keys,
            config.VIRGIL_APP_ID,
            self._app_private_key,
        )
        card = self._client.get_card(created_card.id)
        self.assertEqual(
            card.id,
            created_card.id
        )
        self.assertEqual(
            card.public_key,
            created_card.public_key
        )
        self.assertEqual(
            card.identity,
            created_card.identity
        )
        self.assertEqual(
            card.identity_type,
            created_card.identity_type
        )
        self.cleanup_cards(created_card)

    def test_search_card_by_identity(self):
        alice_keys1 = self._crypto.generate_keys()
        alice_card1 = self._client.create_card(
            "alice",
            "username",
            alice_keys1,
            config.VIRGIL_APP_ID,
            self._app_private_key,
        )

        alice_keys2 = self._crypto.generate_keys()
        alice_card2 = self._client.create_card(
            "alice",
            "username",
            alice_keys2,
            config.VIRGIL_APP_ID,
            self._app_private_key,
        )
        cards = self._client.search_cards_by_identities('alice')
        self.assertIn(alice_card1, cards)
        self.assertIn(alice_card2, cards)
        self.cleanup_cards(*cards)

    def test_search_card_by_multiple_identities(self):
        alice_keys = self._crypto.generate_keys()
        alice_card = self._client.create_card(
            "alice",
            "username",
            alice_keys,
            config.VIRGIL_APP_ID,
            self._app_private_key,
        )

        bob_keys = self._crypto.generate_keys()
        bob_card = self._client.create_card(
            "bob",
            "username",
            bob_keys,
            config.VIRGIL_APP_ID,
            self._app_private_key,
        )
        cards = self._client.search_cards_by_identities('alice', 'bob')
        self.assertIn(alice_card, cards)
        self.assertIn(bob_card, cards)
        self.cleanup_cards(*cards)

    def test_search_card_by_app_bundle(self):
        cards = self._client.search_cards_by_app_bundle(config.VIRGIL_APP_BUNDLE)
        self.assertEqual(
            config.VIRGIL_APP_BUNDLE,
            cards[0].identity
        )

    def cleanup_cards(self, *cards):
        for card in cards:
            self._client.revoke_card(
                card_id=card.id,
                app_id=config.VIRGIL_APP_ID,
                app_key=self._app_private_key,
            )

    @property
    def _client(self):
        if self.__client:
            return self.__client

        self.__client = VirgilClient(
            access_token=config.VIRGIL_ACCESS_TOKEN,
        )
        return self.__client
