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
import unittest

from virgil_sdk.api import Credentials
from virgil_sdk.api import VirgilBuffer
from virgil_sdk.api import VirgilCard
from virgil_sdk.api import VirgilContext
from virgil_sdk.api import VirgilKey
from virgil_sdk.client import Card
from virgil_sdk.client import RequestSigner
from virgil_sdk.client import VirgilClient
from virgil_sdk.client.requests import CreateCardRequest
from virgil_sdk.client.requests import CreateGlobalCardRequest
from virgil_sdk.client.requests import RevokeCardRequest
from virgil_sdk.cryptography import VirgilCrypto
from test.client import config


class VirgilCardTest(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(VirgilCardTest, self).__init__(*args, **kwargs)
        self._context = None
        self._app_private_key = None
        self.__crypto = VirgilCrypto()
        self.__client = VirgilClient(access_token=config.VIRGIL_ACCESS_TOKEN)
        self.__request_signer = RequestSigner(self.__crypto)
        self.__key_pair = self.__crypto.generate_keys()

    def test_encrypt(self):
        card_model = self.__get_card_model(Card.Scope.APPLICATION)
        data_string = "hello world"
        data = VirgilBuffer.from_string(data_string)
        vc = VirgilCard(self.__context, card_model)
        cipher_data = vc.encrypt(data)
        self.assertEqual(
            bytearray(self.__crypto.decrypt(cipher_data.get_bytearray(), self.__key_pair.private_key)),
            data.get_bytearray()
         )

    def test_verify(self):
        card_model = self.__get_card_model(Card.Scope.APPLICATION)
        data_string = "hello world"
        data = VirgilBuffer.from_string(data_string)
        vc = VirgilCard(self.__context, card_model)
        signature = self.__crypto.sign(data.get_bytearray(), self.__key_pair.private_key)
        self.assertTrue(vc.verify(data, VirgilBuffer(signature)))

    def test_publish(self):
        card_model = self.__get_card_model(scope=Card.Scope.APPLICATION)
        creds = Credentials(
            config.VIRGIL_APP_ID,
            self.__crypto.strtobytes(open(config.VIRGIL_APP_KEY_PATH, "r").read()),
            config.VIRGIL_APP_KEY_PASSWORD
        )
        context = VirgilContext(access_token=config.VIRGIL_ACCESS_TOKEN, credentials=creds)
        vc = VirgilCard(context, card_model)

        try:
            vc.publish()
            self.assertIsNotNone(self.__client.get_card(card_model.id))
        finally:
            try:
                self.__cleanup_cards(card_model)
            except Exception:
                pass

    def __build_card_model(self, identity, identity_type, scope, owner_key, custom_fields=None):
        card_config = {
            'identity': identity,
            'identity_type': identity_type,
            'public_key': tuple(owner_key.export_public_key().get_bytearray()),
            'data': custom_fields,
        }

        card = Card(**card_config)
        if scope == Card.Scope.APPLICATION:
            card_request = CreateCardRequest(**card_config)
        elif scope == Card.Scope.GLOBAL:
            card_request = CreateGlobalCardRequest(**card_config)
        else:
            raise ValueError("Unknown scope value")
        card.snapshot = card_request.snapshot
        snapshot_fingerprint = self.__crypto.calculate_fingerprint(card.snapshot)
        card.scope = scope
        card.id = snapshot_fingerprint.to_hex
        self_signature = owner_key.sign(VirgilBuffer(snapshot_fingerprint.value))
        card.signatures = {card.id: self_signature.to_string("base64")}
        return card

    def __cleanup_cards(self, *cards):
        for card in cards:
            request = RevokeCardRequest(
                card_id=card.id,
            )
            self.__request_signer.authority_sign(request, config.VIRGIL_APP_ID, self.__app_private_key)
            self.__client.revoke_card_from_request(request)

    def __get_card_model(self, scope):
        identity = "alice"
        identity_type = "username"
        scope = scope
        owner_key = VirgilKey(self.__context, self.__key_pair.private_key)
        self._card_model = self.__build_card_model(identity, identity_type, scope, owner_key)
        return self._card_model

    @property
    def __context(self):
        return VirgilContext()

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
