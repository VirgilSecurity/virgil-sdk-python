# Copyright (C) 2016-2017 Virgil Security Inc.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
from test.client import config
from test.client.base_test import BaseTest
from virgil_sdk.client import RequestSigner
from virgil_sdk.client.requests import CreateCardRequest
from virgil_sdk.client.requests import RevokeCardRequest
from virgil_sdk.client import VirgilClient
from virgil_sdk.client import CardValidator
from virgil_sdk.cryptography import VirgilCrypto


class VirgilClientTest(BaseTest):
    def __init__(self, *args, **kwargs):
        super(VirgilClientTest, self).__init__(*args, **kwargs)
        self.__client = None
        self.__request_signer = None

    def test_create_card_saves_public_key(self):
        alice_keys = self._crypto.generate_keys()
        virgil_app_id = config.VIRGIL_APP_ID
        create_card_request = CreateCardRequest(
            identity="alice",
            identity_type="username",
            public_key=self._crypto.export_public_key(alice_keys.public_key)
        )
        self._request_signer.self_sign(
            create_card_request,
            alice_keys.private_key
        )
        self._request_signer.authority_sign(
            create_card_request,
            virgil_app_id,
            self._app_private_key
        )

        card = self._client.create_card_from_request(create_card_request)
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
        virgil_app_id = config.VIRGIL_APP_ID
        create_card_request = CreateCardRequest(
            "alice",
            "username",
            self._crypto.export_public_key(alice_keys.public_key)
        )
        self._request_signer.self_sign(
            create_card_request,
            alice_keys.private_key
        )
        self._request_signer.authority_sign(
            create_card_request,
            virgil_app_id,
            self._app_private_key
        )
        card = self._client.create_card_from_request(create_card_request)

        revoke_card_request = RevokeCardRequest(
            card_id=card.id
        )
        self._request_signer.authority_sign(revoke_card_request, config.VIRGIL_APP_ID, self._app_private_key)
        self._client.revoke_card_from_request(revoke_card_request)

    def test_get_card(self):
        alice_keys = self._crypto.generate_keys()
        virgil_app_id = config.VIRGIL_APP_ID
        create_card_request = CreateCardRequest(
            "alice",
            "username",
            self._crypto.export_public_key(alice_keys.public_key)
        )
        self._request_signer.self_sign(
            create_card_request,
            alice_keys.private_key
        )
        self._request_signer.authority_sign(
            create_card_request,
            virgil_app_id,
            self._app_private_key
        )
        created_card = self._client.create_card_from_request(create_card_request)
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
        virgil_app_id = config.VIRGIL_APP_ID

        alice_keys1 = self._crypto.generate_keys()
        create_card_request1 = CreateCardRequest(
            "alice",
            "username",
            self._crypto.export_public_key(alice_keys1.public_key)
        )
        self._request_signer.self_sign(
            create_card_request1,
            alice_keys1.private_key
        )
        self._request_signer.authority_sign(
            create_card_request1,
            virgil_app_id,
            self._app_private_key
        )
        alice_card1 = self._client.create_card_from_request(create_card_request1)

        alice_keys2 = self._crypto.generate_keys()
        create_card_request2 = CreateCardRequest(
            "alice",
            "username",
            self._crypto.export_public_key(alice_keys2.public_key)
        )
        self._request_signer.self_sign(
            create_card_request2,
            alice_keys2.private_key
        )
        self._request_signer.authority_sign(
            create_card_request2,
            virgil_app_id,
            self._app_private_key
        )
        alice_card2 = self._client.create_card_from_request(create_card_request2)

        cards = self._client.search_cards_by_identities('alice')
        self.assertIn(alice_card1, cards)
        self.assertIn(alice_card2, cards)
        self.cleanup_cards(*cards)

    def test_search_card_by_multiple_identities(self):
        virgil_app_id = config.VIRGIL_APP_ID

        alice_keys = self._crypto.generate_keys()
        create_card_request_alice = CreateCardRequest(
            "alice",
            "username",
            self._crypto.export_public_key(alice_keys.public_key)
        )
        self._request_signer.self_sign(
            create_card_request_alice,
            alice_keys.private_key
        )
        self._request_signer.authority_sign(
            create_card_request_alice,
            virgil_app_id,
            self._app_private_key
        )
        alice_card = self._client.create_card_from_request(create_card_request_alice)

        bob_keys = self._crypto.generate_keys()
        create_card_request_bob = CreateCardRequest(
            "bob",
            "username",
            self._crypto.export_public_key(bob_keys.public_key)
        )
        self._request_signer.self_sign(
            create_card_request_bob,
            bob_keys.private_key
        )
        self._request_signer.authority_sign(
            create_card_request_bob,
            virgil_app_id,
            self._app_private_key
        )
        bob_card = self._client.create_card_from_request(create_card_request_bob)
        cards = self._client.search_cards_by_identities('alice', 'bob')
        self.assertIn(alice_card, cards)
        self.assertIn(bob_card, cards)
        self.cleanup_cards(*cards)

    def cleanup_cards(self, *cards):
        for card in cards:
            request = RevokeCardRequest(
                card_id=card.id,
            )
            self._request_signer.authority_sign(request, config.VIRGIL_APP_ID, self._app_private_key)
            self._client.revoke_card_from_request(request)

    @property
    def _client(self):
        if self.__client:
            return self.__client

        self.__client = VirgilClient(
            access_token=config.VIRGIL_ACCESS_TOKEN,
        )
        self.__client.card_validator = (CardValidator(VirgilCrypto()))
        return self.__client

    @property
    def _request_signer(self):
        if self.__request_signer:
            return self.__request_signer

        self.__request_signer = RequestSigner(VirgilCrypto())
        return self.__request_signer
