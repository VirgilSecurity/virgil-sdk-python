# Copyright (C) 2016 Virgil Security Inc.
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
import json
import os
import unittest
from test.client import config
from virgil_sdk.api import Credentials
from virgil_sdk.api import IdentitiesManager
from virgil_sdk.api import VirgilCard

from virgil_sdk.api import VirgilContext
from virgil_sdk.api import VirgilKey
from virgil_sdk.api import CardManager
from virgil_sdk.client import RequestSigner
from virgil_sdk.client import VirgilClient
from virgil_sdk.client.requests import RevokeCardRequest
from virgil_sdk.cryptography import VirgilCrypto

try:
    basestring
except NameError:
    basestring=str

class CardManagerTest(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(CardManagerTest, self).__init__(*args, **kwargs)
        self._context = None
        self.__key_pair_alice = self.__context.crypto.generate_keys()
        self.__key_pair_bob = self.__context.crypto.generate_keys()
        self.__global_card_config = {
            "identity": "bob",
            "identity_type": "email",
            "owner_key": VirgilKey(self.__context, self.__key_pair_bob.private_key)
        }
        self._app_private_key = None
        self.__crypto = VirgilCrypto()
        self.__client = VirgilClient(access_token=config.VIRGIL_ACCESS_TOKEN)
        self.__request_signer = RequestSigner(self.__crypto)
        self._compatibility_data = None
        self._compatibility_data_path = None
        self._decode_data = None

    def test_create_user(self):
        identity = IdentitiesManager().create_user("alice", "username")
        owner_key = VirgilKey(self.__context, self.__key_pair_alice.private_key)
        cm = CardManager(self.__context)
        card = cm.create(identity, owner_key)
        self.assertIsInstance(card, VirgilCard)

    def test_create_email(self):
        identity = IdentitiesManager().create_email("bob@localhost")
        identity._validation_token = "test_token"
        owner_key = VirgilKey(self.__context, self.__key_pair_alice.private_key)
        cm = CardManager(self.__context)
        card = cm.create(identity, owner_key)
        self.assertIsInstance(card, VirgilCard)

    def test_create_app(self):
        identity = IdentitiesManager().create_app("someapp")
        owner_key = VirgilKey(self.__context, self.__key_pair_alice.private_key)
        cm = CardManager(self.__context)
        card = cm.create(identity, owner_key)
        self.assertIsInstance(card, VirgilCard)

    def test_find(self):
        cm = CardManager(self.__context)
        identity = IdentitiesManager().create_user("alice", "username")
        owner_key = VirgilKey(self.__context, self.__key_pair_alice.private_key)
        card = cm.create(identity, owner_key)
        try:
            cm.publish(card)
            finded = cm.find("alice")
            self.assertIn(card, finded)
        finally:
            try:
                self.__cleanup_cards(card)
            except Exception:
                pass

    def test_import_card_unpublished_local(self):
        data = self.__compatibility_data["export_unpublished_local_virgil_card"]
        cm = CardManager(self.__context)
        imported_card = cm.import_card(data["exported_card"])
        self.assertEqual(imported_card.id, data["card_id"])

    def test_import_card_published_global(self):
        data = self.__compatibility_data["export_published_global_virgil_card"]
        cm = CardManager(self.__context)
        imported_card = cm.import_card(data["exported_card"])
        self.assertEqual(imported_card, cm.get(data["card_id"]))

    def test_publish(self):
        cm = CardManager(self.__context)
        identity = IdentitiesManager().create_user("alice", "username")
        owner_key = VirgilKey(self.__context, self.__key_pair_alice.private_key)
        card = cm.create(identity, owner_key)

        try:
            card.publish()
            self.assertIsInstance(cm.get(card.id), VirgilCard)
            self.assertEqual(cm.get(card.id).identity, card.identity)
        finally:
            try:
                self.__cleanup_cards(card)
            except Exception:
                pass

    def test_revoke(self):
        cm = CardManager(self.__context)
        identity = IdentitiesManager().create_user("alice", "username")
        owner_key = VirgilKey(self.__context, self.__key_pair_alice.private_key)
        card = cm.create(identity, owner_key)
        try:
            card.publish()
            self.assertIsInstance(cm.get(card.id), VirgilCard)
            self.assertEqual(cm.get(card.id).identity, card.identity)
            cm.revoke(card)
            with self.assertRaises(Exception) as context:
                cm.get(card.id)
            self.assertTrue("" in str(context.exception))
        finally:
            try:
                self.__cleanup_cards(card)
            except Exception:
                pass

    def __cleanup_cards(self, *cards):
        for card in cards:
            request = RevokeCardRequest(
                card_id=card.id,
            )
            self.__request_signer.authority_sign(request, config.VIRGIL_APP_ID, self.__app_private_key)
            self.__client.revoke_card_from_request(request)

    @property
    def __context(self):
        if not self._context:
            creds = Credentials(
                config.VIRGIL_APP_ID,
                open(config.VIRGIL_APP_KEY_PATH, "rb").read(),
                config.VIRGIL_APP_KEY_PASSWORD
            )
            self._context = VirgilContext(
                config.VIRGIL_ACCESS_TOKEN,
                creds
            )
        return self._context

    @property
    def __app_private_key(self):
        if self._app_private_key:
            return self._app_private_key
        with open(config.VIRGIL_APP_KEY_PATH, "r") as key_file:
            raw_private_key = self.__crypto.strtobytes(key_file.read())

        self._app_private_key = self.__crypto.import_private_key(
            key_data=raw_private_key,
            password=config.VIRGIL_APP_KEY_PASSWORD
        )
        return self._app_private_key

    @property
    def __compatibility_data(self):
        if self._compatibility_data:
            return self._compatibility_data
        with open(self.__compatibility_data_path, "r") as data_file:
            raw_data = data_file.read()

        json_data = json.loads(raw_data)
        return json_data

    @property
    def __compatibility_data_path(self):
        if self._compatibility_data_path:
            return self._compatibility_data_path
        this_file_path = os.path.abspath(__file__)
        cwd = os.path.dirname(this_file_path)
        data_file_path = os.path.join(
            cwd,
            "..",
            "data",
            "sdk_compatibility_data.json"
        )
        self._compatibility_data_path = data_file_path
        return data_file_path
