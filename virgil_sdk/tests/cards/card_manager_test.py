# Copyright (C) 2016-2018 Virgil Security Inc.
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
import binascii
import datetime
import os
import uuid

from virgil_crypto.access_token_signer import AccessTokenSigner
from virgil_crypto.card_crypto import CardCrypto

from virgil_sdk.tests import config
from virgil_sdk.tests.base_test import BaseTest
from virgil_sdk.cards import RawCardContent
from virgil_sdk.client import RawSignedModel, ClientException
from virgil_sdk import CardManager, VirgilCardVerifier
from virgil_sdk.jwt import JwtGenerator
from virgil_sdk.signers import ModelSigner
from virgil_sdk.utils import Utils
from virgil_sdk.verification import CardVerificationException


class CardManagerTest(BaseTest):

    class FakeTokenProvider(object):

        def __init__(self, token_generator, additional_token_generator=None):
            self.token_generator = token_generator
            self.additional_token_generator = additional_token_generator

        def get_token(self, token_context):
            if not token_context.force_reload and self.additional_token_generator:
                token = self.additional_token_generator.generate_token(str(binascii.hexlify(os.urandom(20)).decode()))
                return token
            token = self.token_generator.generate_token(str(binascii.hexlify(os.urandom(20)).decode()))
            return token

    class EchoTokenProvider(object):

        def __init__(self, token):
            self._token = token

        def get_token(self, token_context):
            return self._token

    class NegativeVerifier(object):

        @staticmethod
        def verify_card(card):
            return False

    def test_create_card_register_new_card_on_service(self):
        card = self.publish_card("alice-" + str(uuid.uuid4()))
        self.assertIsNotNone(card)
        got_card = self.get_card(card.id)
        self.assertEqual(card.content_snapshot, got_card.content_snapshot)
        self.assertEqual(card.signatures[0].signer, ModelSigner.SELF_SIGNER)
        self.assertEqual(got_card.signatures[0].signer, ModelSigner.SELF_SIGNER)
        self.assertEqual(len(got_card.signatures), 2)

    def test_create_card_with_previous_card_id_register_new_card_with_previous_card_id(self):
        alice_name = "alice-" + str(uuid.uuid4())
        alica_card = self.publish_card(alice_name)
        new_alice_card = self.publish_card(alice_name, alica_card.id)
        self.assertEqual(new_alice_card.previous_card_id, alica_card.id)

    def test_previous_card_id_outdated(self):
        alice_name = "alice-" + str(uuid.uuid4())
        alica_card = self.publish_card(alice_name)
        new_alice_card = self.publish_card(alice_name, alica_card.id)
        outdated_card = self.get_card(alica_card.id)
        self.assertTrue(outdated_card.is_outdated)

    def test_search_card_by_identity_with_two_related_cards_return_one_actual_cards(self):
        alice_name = "alice-" + str(uuid.uuid4())
        alice_card = self.publish_card(alice_name)
        new_alice_card = self.publish_card(alice_name, alice_card.id)
        cards = self.search_card(alice_name)
        self.assertEqual(len(cards), 1)
        actual_card = cards[0]
        self.assertEqual(actual_card.id, new_alice_card.id)
        self.assertEqual(actual_card.previous_card_id, alice_card.id)
        self.assertTrue(actual_card.previous_card.is_outdated)

    def test_create_card_with_invalid_previous_card_id(self):
        alice_name = "alice-" + str(uuid.uuid4())
        self.assertRaises(
            ClientException,
            self.publish_card,
            alice_name,
            "invalid_previous_card_id"
        )

    def test_create_card_with_non_unique_previous_card_id(self):
        alice_name = "alice-" + str(uuid.uuid4())
        prev_card = self.publish_card(alice_name)
        self.publish_card(alice_name, prev_card.id)
        self.assertRaises(
            ClientException,
            self.publish_card,
            alice_name,
            prev_card.id
        )

    def test_create_card_with_wrong_identity_in_previous_card(self):
        alice_name = "alice-" + str(uuid.uuid4())
        prev_card = self.publish_card(alice_name)
        self.assertRaises(
            ClientException,
            self.publish_card,
            "new-" + alice_name,
            prev_card.id
        )

    def test_get_card_with_wrong_id(self):
        self.assertRaises(
            ClientException,
            self.get_card,
            "invalid_card_id"
        )

    def test_search_card_with_wrong_identity(self):
        cards = self.search_card("invalid_identity")
        self.assertEqual(len(cards), 0)

    def test_search_cards_return_same_card(self):
        alice_name = "alice-" + str(uuid.uuid4())
        card = self.publish_card(alice_name)
        alice_cards = self.search_card(alice_name)
        self.assertEqual(len(alice_cards), 1)
        self.assertEqual(alice_cards[0].id, card.id)

    def test_import_pure_card_from_string_create_equivalent_card(self):
        key_pair = self._crypto.generate_keys()
        raw_signed_model = self._data_generator.generate_raw_signed_model(key_pair)
        card_manager = self._data_generator.generate_card_manager()
        raw_signed_model_string = raw_signed_model.to_string()
        card = card_manager.import_card(raw_signed_model_string)
        exported_card_string = card_manager.export_card_to_string(card)
        self.assertEqual(exported_card_string, raw_signed_model_string)

    def test_import_pure_card_from_json_create_equivalent_card(self):
        key_pair = self._crypto.generate_keys()
        raw_signed_model = self._data_generator.generate_raw_signed_model(key_pair, True)
        card_manager = self._data_generator.generate_card_manager()
        raw_signed_model_json = raw_signed_model.to_json()
        card = card_manager.import_card(raw_signed_model_json)
        exported_card_json = card_manager.export_card_to_json(card)
        self.assertEqual(exported_card_json, raw_signed_model_json)

    def test_import_full_card_from_string_create_equivalent_card(self):
        key_pair = self._crypto.generate_keys()
        additional_key_pair = self._crypto.generate_keys()
        raw_signed_model = self._data_generator.generate_raw_signed_model(key_pair, True, key_pair, additional_key_pair)
        card_manager = self._data_generator.generate_card_manager()
        raw_signed_model_string = raw_signed_model.to_string()
        card = card_manager.import_card(raw_signed_model_string)
        exported_card_string = card_manager.export_card_to_string(card)
        self.assertEqual(exported_card_string, raw_signed_model_string)

    def test_import_full_card_from_json_create_equivalent_card(self):
        key_pair = self._crypto.generate_keys()
        additional_key_pair = self._crypto.generate_keys()
        raw_signed_model = self._data_generator.generate_raw_signed_model(key_pair, True, key_pair, additional_key_pair)
        card_manager = self._data_generator.generate_card_manager()
        raw_signed_model_json = raw_signed_model.to_json()
        card = card_manager.import_card(raw_signed_model_json)
        exported_card_json = card_manager.export_card_to_json(card)
        self.assertEqual(exported_card_json, raw_signed_model_json)

    def test_expired_token(self):
        token_generator = JwtGenerator(
            config.VIRGIL_APP_ID,
            self._app_private_key,
            config.VIRGIL_API_KEY_ID,
            0,
            AccessTokenSigner()
        )
        access_token_provider = self.FakeTokenProvider(token_generator)
        card_manager = self._data_generator.generate_card_manager(access_token_provider)
        self.assertRaises(
            ClientException,
            card_manager.get_card,
            self._data_generator.generate_card_id()
        )

    def test_send_second_request_to_client_expired_token_retry_on_unauthorized(self):
        class FakeTokenProvider(object):
            def __init__(self, identity, token_generator, additional_token_generator=None):
                self.identity = identity
                self.token_generator = token_generator
                self.additional_token_generator = additional_token_generator

            def get_token(self, token_context):
                if not token_context.force_reload and self.additional_token_generator:
                    token = self.additional_token_generator.generate_token(
                        identity
                    )
                    return token
                token = self.token_generator.generate_token(identity)
                return token

        expired_jwt_generator = JwtGenerator(
            config.VIRGIL_APP_ID,
            self._app_private_key,
            config.VIRGIL_API_KEY_ID,
            1,
            AccessTokenSigner()
        )

        jwt_generator = JwtGenerator(
            config.VIRGIL_APP_ID,
            self._app_private_key,
            config.VIRGIL_API_KEY_ID,
            datetime.timedelta(minutes=10).seconds,
            AccessTokenSigner()
        )

        identity = str(binascii.hexlify(os.urandom(20)).decode())

        access_token_provider = FakeTokenProvider(identity, jwt_generator, expired_jwt_generator)
        validator = VirgilCardVerifier(CardCrypto())
        card_manager = CardManager(
            card_crypto=CardCrypto(),
            access_token_provider=access_token_provider,
            card_verifier=validator,
            sign_callback=self.sign_callback
        )
        key_pair = self._crypto.generate_keys()
        card = card_manager.publish_card(
            key_pair.private_key,
            key_pair.public_key,
            identity
        )
        self.assertIsNotNone(card)
        searched_card = card_manager.search_card(identity)
        self.assertEqual(len(searched_card), 1)

    def test_get_invalid_card(self):
        class FakeCardClient(object):

            def __init__(self, raw_signed_model):
                self._raw_signed_model = raw_signed_model

            def publish_card(self, raw_signed_model, access_token):
                return self._raw_signed_model

            def get_card(self, card_id, access_token):
                return self._raw_signed_model, False

            def search_card(self, identity, access_token):
                return [self._raw_signed_model]

        validator = self.NegativeVerifier()
        jwt_generator = JwtGenerator(
            config.VIRGIL_APP_ID,
            self._app_private_key,
            config.VIRGIL_API_KEY_ID,
            datetime.timedelta(minutes=10).seconds,
            AccessTokenSigner()
        )

        identity = Utils.b64encode(os.urandom(20))
        token = jwt_generator.generate_token(identity)
        access_token_provider = self.EchoTokenProvider(token)
        key_pair = self._crypto.generate_keys()
        virgil_key_pair = self._crypto.generate_keys()
        additional_key_pair = self._crypto.generate_keys()
        model = self._data_generator.generate_raw_signed_model(key_pair, True, virgil_key_pair, additional_key_pair)
        client = FakeCardClient(model)

        card_id = self._data_generator.generate_card_id()
        search_identity = Utils.b64encode(os.urandom(20))
        manager = CardManager(
            CardCrypto(),
            access_token_provider,
            validator,
            sign_callback=self.sign_callback
        )
        manager._card_client = client
        self.assertRaises(CardVerificationException, manager.import_card, model.to_json())
        self.assertRaises(CardVerificationException, manager.import_card, model.to_string())
        self.assertRaises(CardVerificationException, manager.get_card, card_id)
        self.assertRaises(CardVerificationException, manager.publish_card, model)
        self.assertRaises(CardVerificationException, manager.search_card, search_identity)
        self.assertRaises(CardVerificationException, manager.import_card, model)

    def test_gets_card_with_different_id(self):

        class PositiveVerifier(object):

            def verify_card(self):
                return True

        class FakeCardClient(object):

            def __init__(self, raw_signed_model):
                self._raw_signed_model = raw_signed_model

            def get_card(self, card_id, access_token):
                return self._raw_signed_model, False

        validator = PositiveVerifier()
        key_pair = self._crypto.generate_keys()
        raw_card_content = RawCardContent(
            identity="test",
            public_key=key_pair.public_key,
            created_at=Utils.to_timestamp(datetime.datetime.now()),
            version="5.0"
        )
        model = RawSignedModel(raw_card_content.content_snapshot)
        signer = ModelSigner(CardCrypto())
        signer.self_sign(model, key_pair.private_key, extra_fields={"info": "some_additional_info"})
        jwt_generator = JwtGenerator(
            config.VIRGIL_APP_ID,
            self._app_private_key,
            config.VIRGIL_API_KEY_ID,
            datetime.timedelta(minutes=10).seconds,
            AccessTokenSigner()
        )
        identity = Utils.b64encode(os.urandom(20))
        token = jwt_generator.generate_token(identity)
        access_token_provider = self.EchoTokenProvider(token)
        card_id = self._data_generator.generate_app_id()
        manager = CardManager(
            card_crypto=CardCrypto(),
            access_token_provider=access_token_provider,
            card_verifier=validator,
        )
        manager.card_client = FakeCardClient(model)
        self.assertRaises(CardVerificationException, manager.get_card, card_id)
