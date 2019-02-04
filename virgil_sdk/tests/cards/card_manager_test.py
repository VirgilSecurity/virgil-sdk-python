# Copyright (C) 2016-2019 Virgil Security Inc.
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
from base64 import b64decode
from time import sleep

from virgil_crypto.access_token_signer import AccessTokenSigner
from virgil_crypto.card_crypto import CardCrypto

from virgil_sdk.jwt.providers import CallbackJwtProvider, CachingCallbackProvider
from virgil_sdk.tests import config
from virgil_sdk.tests.base_test import BaseTest
from virgil_sdk.cards import RawCardContent, Card
from virgil_sdk.client import RawSignedModel, ClientException, ExpiredAuthorizationClientException
from virgil_sdk import CardManager, VirgilCardVerifier
from virgil_sdk.jwt import JwtGenerator, TokenContext
from virgil_sdk.signers import ModelSigner
from virgil_sdk.utils import Utils
from virgil_sdk.verification import CardVerificationException


class SlowedCardManager(CardManager):
    def __init__(self, *args, **kwargs):
        super(SlowedCardManager, self).__init__(*args, **kwargs)
        self.__retry_on_unauthorized = kwargs.get("retry_on_unauthorized", False)
        self.__api_url = kwargs.get("api_url", "https://api.virgilsecurity.com")

    def __try_execute(self, card_function, card_arg, token, context):
        # type: (function, Any, str, TokenContext) -> Any
        attempts_number = 2 if self.__retry_on_unauthorized else 1
        result = None
        while attempts_number > 0:
            try:
                result = card_function(card_arg, token)
            except ExpiredAuthorizationClientException as e:
                token = self._access_token_provider.get_token(context)
                if attempts_number - 1 < 1:
                    raise e
            attempts_number -= 1
        return result

    def get_card(self, card_id):
        token_context = TokenContext(None, "get")
        access_token = self._access_token_provider.get_token(token_context)
        sleep(2)
        raw_card, is_outdated = self.__try_execute(self.card_client.get_card, card_id, access_token,
                                                   token_context)
        card = Card.from_signed_model(self._card_crypto, raw_card, is_outdated)
        if card.id != card_id:
            raise CardVerificationException("Invalid card")
        self.__validate(card)
        return card


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

    class PositiveVerifier(object):

        @staticmethod
        def verify_card(card):
            return True

    class NegativeVerifier(object):

        @staticmethod
        def verify_card(card):
            return False

    def test_negative_verify(self):
        # STC-13
        key_pair = self._crypto.generate_keys()
        manager = CardManager(
            CardCrypto(),
            api_url=config.VIRGIL_API_URL,
            access_token_provider=CallbackJwtProvider(self._get_token_from_server),
            sign_callback=self.sign_callback,
            card_verifier=self.NegativeVerifier()
        )

        self.assertRaises(
            CardVerificationException,
            manager.import_card,
            self._compatibility_data["STC-3.as_string"]
        )
        self.assertRaises(
            CardVerificationException,
            manager.import_card,
            self._compatibility_data["STC-3.as_json"]
        )

        card_identity = "alice-" + str(uuid.uuid4())
        self.assertRaises(
            CardVerificationException,
            manager.publish_card,
            key_pair.private_key,
            key_pair.public_key,
            card_identity
        )
        self.assertRaises(
            CardVerificationException,
            manager.publish_card,
            self._data_generator.generate_raw_signed_model(key_pair, True)
        )

        # publish card with normal verifier
        published_card = self.publish_card("alice-" + str(uuid.uuid4()))

        self.assertRaises(
            CardVerificationException,
            manager.get_card,
            published_card.id
        )
        self.assertRaises(
            CardVerificationException,
            manager.search_card,
            card_identity
        )

    def test_create_card_register_new_card_on_service(self):
        # STC-17
        key_pair = self._crypto.generate_keys()

        validator = VirgilCardVerifier(CardCrypto())
        if config.VIRGIL_CARD_SERVICE_PUBLIC_KEY:
            validator._VirgilCardVerifier__virgil_public_key_base64 = config.VIRGIL_CARD_SERVICE_PUBLIC_KEY

        manager = CardManager(
            CardCrypto(),
            api_url=config.VIRGIL_API_URL,
            access_token_provider=CallbackJwtProvider(self._get_token_from_server),
            sign_callback=self.sign_callback,
            card_verifier=validator,
        )

        card = manager.publish_card(
            identity="alice-" + str(uuid.uuid4()),
            public_key=key_pair.public_key,
            private_key=key_pair.private_key,
        )
        self.assertIsNotNone(card)
        got_card = self.get_card(card.id)
        self.assertEqual(card.content_snapshot, got_card.content_snapshot)
        self.assertEqual(card.signatures[0].signer, ModelSigner.SELF_SIGNER)
        self.assertEqual(got_card.signatures[0].signer, ModelSigner.SELF_SIGNER)
        self.assertFalse(got_card.is_outdated)
        self.assertEqual(len(got_card.signatures), 2)

    def test_create_card_register_new_card_on_service_with_meta(self):
        # STC-18
        key_pair = self._crypto.generate_keys()

        provider = CachingCallbackProvider(self._get_token_from_server, 10)
        validator = VirgilCardVerifier(CardCrypto())
        if config.VIRGIL_CARD_SERVICE_PUBLIC_KEY:
            validator._VirgilCardVerifier__virgil_public_key_base64 = config.VIRGIL_CARD_SERVICE_PUBLIC_KEY

        card_manager = CardManager(
            CardCrypto(),
            api_url=config.VIRGIL_API_URL,
            access_token_provider=provider,
            card_verifier=validator
        )
        card = card_manager.publish_card(
            identity="alice-" + str(uuid.uuid4()),
            public_key=key_pair.public_key,
            private_key=key_pair.private_key,
            extra_fields={
                "some_meta_key": "some_meta_val"
            }
        )
        self.assertIsNotNone(card)
        got_card = self.get_card(card.id)
        self.assertEqual(card.content_snapshot, got_card.content_snapshot)
        self.assertEqual(card.signatures[0].signer, ModelSigner.SELF_SIGNER)
        self.assertEqual(got_card.signatures[0].signer, ModelSigner.SELF_SIGNER)
        self.assertEqual(len(got_card.signatures), 2)

    def test_create_card_with_previous_card_id_register_new_card_with_previous_card_id(self):
        # STC-19
        alice_name = "alice-" + str(uuid.uuid4())
        alica_card = self.publish_card(alice_name)
        new_alice_card = self.publish_card(alice_name, alica_card.id)
        self.assertEqual(new_alice_card.previous_card_id, alica_card.id)

    def test_previous_card_id_outdated(self):
        # STC-19
        alice_name = "alice-" + str(uuid.uuid4())
        alica_card = self.publish_card(alice_name)
        new_alice_card = self.publish_card(alice_name, alica_card.id)
        outdated_card = self.get_card(alica_card.id)
        self.assertTrue(outdated_card.is_outdated)

    def test_search_card_by_identity_with_two_related_cards_return_one_actual_cards(self):
        # STC-20
        alice_name = "alice-" + str(uuid.uuid4())
        alice_card = self.publish_card(alice_name)
        new_alice_card = self.publish_card(alice_name, alice_card.id)
        cards = self.search_card(alice_name)
        self.assertEqual(len(cards), 1)
        actual_card = cards[0]
        self.assertEqual(actual_card.id, new_alice_card.id)
        self.assertEqual(actual_card.previous_card_id, alice_card.id)
        self.assertTrue(actual_card.previous_card.is_outdated)

    def test_publish_raw_signed_model(self):
        # STC-21
        validator = VirgilCardVerifier(CardCrypto())
        if config.VIRGIL_CARD_SERVICE_PUBLIC_KEY:
            validator._VirgilCardVerifier__virgil_public_key_base64 = config.VIRGIL_CARD_SERVICE_PUBLIC_KEY

        manager = CardManager(
            CardCrypto(),
            api_url=config.VIRGIL_API_URL,
            access_token_provider=CallbackJwtProvider(self._get_token_from_server),
            sign_callback=self.extra_sign_callback,
            card_verifier=validator
        )

        key_pair = self._crypto.generate_keys()
        alice_name = "alice-" + str(uuid.uuid4())
        raw_card = manager.generate_raw_card(
            key_pair.private_key,
            key_pair.public_key,
            alice_name,
        )
        published_card = manager.publish_card(raw_card)
        self.assertEqual(2, len(raw_card.signatures))
        got_card = manager.get_card(published_card.id)
        self.assertEqual(got_card.identity, alice_name)
        self.assertEqual(got_card.public_key, key_pair.public_key)
        self.assertFalse(got_card.is_outdated)

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
        # STC-34
        self.assertRaises(
            ClientException,
            self.get_card,
            "invalid_card_id"
        )

    def test_search_card_with_wrong_identity(self):
        # STC-36
        cards = self.search_card("invalid_identity")
        self.assertEqual(len(cards), 0)

    def test_search_cards_return_same_card(self):
        alice_name = "alice-" + str(uuid.uuid4())
        card = self.publish_card(alice_name)
        alice_cards = self.search_card(alice_name)
        self.assertEqual(len(alice_cards), 1)
        self.assertEqual(alice_cards[0].id, card.id)

    def test_search_multiply_cards_by_multiply_identities(self):
        # STC-42
        alice_name = "alice-" + str(uuid.uuid4())
        old_alice_card = self.publish_card(alice_name)
        new_alice_card = self.publish_card(alice_name, old_alice_card.id)
        bob_name = "bob-" + str(uuid.uuid4())
        bob_card = self.publish_card(bob_name)
        found_cards = self.search_card([alice_name, bob_name])
        self.assertEqual(len(found_cards), 2)
        self.assertIsNotNone(new_alice_card.previous_card_id)
        for card in found_cards:
            self.assertIsNotNone(card.content_snapshot)
        self.assertTrue(
            any(
                filter(
                    lambda x: x.content_snapshot == new_alice_card.content_snapshot and x.previous_card,
                    found_cards
                )
            )
        )
        self.assertTrue(
            any(filter(lambda x: x.content_snapshot == bob_card.content_snapshot, found_cards))
        )
        self.assertFalse(new_alice_card.content_snapshot == bob_card.content_snapshot)

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
        raw_signed_model = self._data_generator.generate_raw_signed_model(key_pair, False)
        card_manager = self._data_generator.generate_card_manager()
        raw_signed_model_json = raw_signed_model.to_json()
        card = card_manager.import_card(raw_signed_model_json)
        exported_card_json = card_manager.export_card_to_json(card)
        self.assertEqual(exported_card_json, raw_signed_model_json)

    def test_import_full_card_from_string_create_equivalent_card(self):
        key_pair = self._crypto.generate_keys()
        raw_signed_model = self._data_generator.generate_raw_signed_model(key_pair, False)
        card_manager = self._data_generator.generate_card_manager()
        raw_signed_model_string = raw_signed_model.to_string()
        card = card_manager.import_card(raw_signed_model_string)
        exported_card_string = card_manager.export_card_to_string(card)
        self.assertEqual(exported_card_string, raw_signed_model_string)

    def test_import_full_card_from_json_create_equivalent_card(self):
        key_pair = self._crypto.generate_keys()
        raw_signed_model = self._data_generator.generate_raw_signed_model(key_pair, False)
        card_manager = self._data_generator.generate_card_manager()
        raw_signed_model_json = raw_signed_model.to_json()
        card = card_manager.import_card(raw_signed_model_json)
        exported_card_json = card_manager.export_card_to_json(card)
        self.assertEqual(exported_card_json, raw_signed_model_json)

    def test_expired_token(self):
        # STC-26 negative
        token_generator = JwtGenerator(
            config.VIRGIL_APP_ID,
            self._app_private_key,
            config.VIRGIL_API_PUB_KEY_ID,
            1,
            AccessTokenSigner()
        )
        access_token_provider = self.FakeTokenProvider(token_generator)
        validator = VirgilCardVerifier(CardCrypto())
        if config.VIRGIL_CARD_SERVICE_PUBLIC_KEY:
            validator._VirgilCardVerifier__virgil_public_key_base64 = config.VIRGIL_CARD_SERVICE_PUBLIC_KEY
        card_manager = SlowedCardManager(
            card_crypto=CardCrypto(),
            access_token_provider=access_token_provider,
            card_verifier=validator,
            api_url=config.VIRGIL_API_URL,
            sign_callback=self.sign_callback
        )
        self.assertRaises(
            ExpiredAuthorizationClientException,
            card_manager.get_card,
            self._data_generator.generate_card_id()
        )

    def test_send_second_request_to_client_expired_token_retry_on_unauthorized(self):
        # STC-26
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
            config.VIRGIL_API_PUB_KEY_ID,
            1,
            AccessTokenSigner()
        )

        jwt_generator = JwtGenerator(
            config.VIRGIL_APP_ID,
            self._app_private_key,
            config.VIRGIL_API_PUB_KEY_ID,
            datetime.timedelta(minutes=10).seconds,
            AccessTokenSigner()
        )

        identity = str(binascii.hexlify(os.urandom(20)).decode())

        access_token_provider = FakeTokenProvider(identity, jwt_generator, expired_jwt_generator)
        validator = VirgilCardVerifier(CardCrypto())
        if config.VIRGIL_CARD_SERVICE_PUBLIC_KEY:
            validator._VirgilCardVerifier__virgil_public_key_base64 = config.VIRGIL_CARD_SERVICE_PUBLIC_KEY
        card_manager = CardManager(
            card_crypto=CardCrypto(),
            access_token_provider=access_token_provider,
            card_verifier=validator,
            api_url=config.VIRGIL_API_URL,
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
            config.VIRGIL_API_PUB_KEY_ID,
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
        # STC-35

        class FakeCardClient(object):

            def __init__(self, raw_signed_model):
                self._raw_signed_model = raw_signed_model

            def get_card(self, card_id, access_token):
                return self._raw_signed_model, False

        validator = self.PositiveVerifier()
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
            config.VIRGIL_API_PUB_KEY_ID,
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

    def test_compatibility_import_export_card(self):
        # STC-3
        card_crypto = CardCrypto()
        card_manager = CardManager(
            card_crypto=card_crypto,
            access_token_provider=self._data_generator.generate_empty_access_token_provider(),
            card_verifier=self.PositiveVerifier()
        )
        card_from_string = card_manager.import_card(self._compatibility_data["STC-3.as_string"])
        card_from_json = card_manager.import_card(self._compatibility_data["STC-3.as_json"])

        self.assertEqual(card_from_string.id, self._compatibility_data["STC-3.card_id"])
        self.assertEqual(card_from_json.id, self._compatibility_data["STC-3.card_id"])

        self.assertEqual(card_from_string.identity, "test")
        self.assertEqual(card_from_json.identity, "test")

        self.assertEqual(
            card_from_string.public_key,
            card_crypto.import_public_key(
                bytearray(Utils.b64decode(self._compatibility_data["STC-3.public_key_base64"]))
            )
        )
        self.assertEqual(
            card_from_json.public_key,
            card_crypto.import_public_key(
                bytearray(Utils.b64decode(self._compatibility_data["STC-3.public_key_base64"]))
            )
        )

        self.assertEqual(card_from_string.version, "5.0")
        self.assertEqual(card_from_json.version, "5.0")

        self.assertEqual(card_from_string.created_at, 1515686245)
        self.assertEqual(card_from_json.created_at, 1515686245)

        self.assertIsNone(card_from_string.previous_card_id)
        self.assertIsNone(card_from_json.previous_card_id)

        self.assertIsNone(card_from_string.previous_card)
        self.assertIsNone(card_from_json.previous_card)

        self.assertEqual(card_from_string.signatures, [])
        self.assertEqual(card_from_json.signatures, [])

        card_exported_string = card_manager.export_card_to_string(card_from_string)
        self.assertEqual(self._compatibility_data["STC-3.as_string"], card_exported_string)

        card_exported_json = card_manager.export_card_to_json(card_from_json)
        self.assertEqual(card_exported_json, self._compatibility_data["STC-3.as_json"])

    def test_compatibility_import_export_card_with_signature(self):
        # STC-4
        card_crypto = CardCrypto()
        card_manager = CardManager(
            card_crypto=card_crypto,
            access_token_provider=self._data_generator.generate_empty_access_token_provider(),
            card_verifier=self.PositiveVerifier()
        )
        card_from_string = card_manager.import_card(self._compatibility_data["STC-4.as_string"])
        card_from_json = card_manager.import_card(self._compatibility_data["STC-4.as_json"])

        self.assertEqual(card_from_string.id, self._compatibility_data["STC-4.card_id"])
        self.assertEqual(card_from_json.id, self._compatibility_data["STC-4.card_id"])

        self.assertEqual(card_from_string.identity, "test")
        self.assertEqual(card_from_json.identity, "test")

        self.assertEqual(
            card_from_string.public_key,
            card_crypto.import_public_key(
                bytearray(Utils.b64decode(self._compatibility_data["STC-4.public_key_base64"]))
            )
        )
        self.assertEqual(
            card_from_json.public_key,
            card_crypto.import_public_key(
                bytearray(Utils.b64decode(self._compatibility_data["STC-4.public_key_base64"]))
            )
        )

        self.assertEqual(card_from_string.version, "5.0")
        self.assertEqual(card_from_json.version, "5.0")

        self.assertEqual(card_from_string.created_at, 1515686245)
        self.assertEqual(card_from_json.created_at, 1515686245)

        self.assertIsNone(card_from_string.previous_card_id)
        self.assertIsNone(card_from_json.previous_card_id)

        self.assertIsNone(card_from_string.previous_card)
        self.assertIsNone(card_from_json.previous_card)

        self.assertEqual(
            card_from_string.signatures[0].signature,
            b64decode(self._compatibility_data["STC-4.signature_self_base64"])
        )
        self.assertEqual(
            card_from_json.signatures[0].signature,
            b64decode(self._compatibility_data["STC-4.signature_self_base64"])
        )

        self.assertEqual(
            card_from_string.signatures[1].signature,
            b64decode(self._compatibility_data["STC-4.signature_virgil_base64"])
        )
        self.assertEqual(
            card_from_json.signatures[1].signature,
            b64decode(self._compatibility_data["STC-4.signature_virgil_base64"])
        )

        self.assertEqual(
            card_from_string.signatures[2].signature,
            b64decode(self._compatibility_data["STC-4.signature_extra_base64"])
        )
        self.assertEqual(
            card_from_json.signatures[2].signature,
            b64decode(self._compatibility_data["STC-4.signature_extra_base64"])
        )

        card_exported_string = card_manager.export_card_to_string(card_from_string)
        self.assertEqual(self._compatibility_data["STC-4.as_string"], card_exported_string)

        card_exported_json = card_manager.export_card_to_json(card_from_json)
        self.assertEqual(card_exported_json, self._compatibility_data["STC-4.as_json"])

    def extra_sign_callback(self, model):
        key_pair = self._crypto.generate_keys()
        model_signer = ModelSigner(CardCrypto())
        model_signer.sign(
            model,
            "extra",
            key_pair.private_key
        )
        return model
