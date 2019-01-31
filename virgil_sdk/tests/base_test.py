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
import json
import os
import unittest

from virgil_crypto.access_token_signer import AccessTokenSigner
from virgil_crypto.card_crypto import CardCrypto
from virgil_sdk.tests import config

from virgil_crypto import VirgilCrypto

from virgil_sdk.tests.data.data_generator import DataGenerator
from virgil_sdk import VirgilCardVerifier, CardManager
from virgil_sdk.client import RawSignedModel
from virgil_sdk.jwt import JwtGenerator
from virgil_sdk.jwt.providers import CallbackJwtProvider
from virgil_sdk.utils import Utils


class BaseTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(BaseTest, self).__init__(*args, **kwargs)
        self.__compatibility_data_path = None
        self.__compatibility_data = None
        self.__app_private_key = None
        self.__crypto = None
        self._data_generator = DataGenerator(self._crypto)

    @property
    def _crypto(self):
        if self.__crypto:
            return self.__crypto
        self.__crypto = VirgilCrypto()
        return self.__crypto

    @property
    def _app_private_key(self):
        if self.__app_private_key:
            return self.__app_private_key
        with open(config.VIRGIL_APP_KEY_PATH, "rb") as key_file:
            raw_private_key = bytearray(Utils.b64decode(key_file.read()))

        self.__app_private_key = self._crypto.import_private_key(
            key_data=raw_private_key,
            password=config.VIRGIL_APP_KEY_PASSWORD
        )
        return self.__app_private_key

    @property
    def _compatibility_data(self):
        if self.__compatibility_data:
            return self.__compatibility_data
        with open(self._compatibility_data_path, "r") as data_file:
            raw_data = data_file.read()

        json_data = json.loads(raw_data)
        return json_data

    @property
    def _compatibility_data_path(self):
        if self.__compatibility_data_path:
            return self.__compatibility_data_path
        this_file_path = os.path.abspath(__file__)
        cwd = os.path.dirname(this_file_path)
        data_file_path = os.path.join(
            cwd,
            "data",
            "data.json"
        )
        self.__compatibility_data_path = data_file_path
        return data_file_path

    def _get_token_from_server(self, token_context, token_ttl=20):
        return self.__emulate_server_jwt_response(token_context, token_ttl)

    def __emulate_server_jwt_response(self, token_context, token_ttl):
        data = {"username": "my_username"}
        builder = JwtGenerator(
            config.VIRGIL_APP_ID,
            self._app_private_key,
            config.VIRGIL_API_PUB_KEY_ID,
            token_ttl,
            AccessTokenSigner()
        )
        identity = self.some_hash(token_context.identity)
        return builder.generate_token(identity, data).to_string()

    def __emulate_server_app_sign_response(self, model_sting):
        raw_signed_model = RawSignedModel.from_string(model_sting)
        return raw_signed_model.to_string()

    @staticmethod
    def some_hash(identity):
        if not identity:
            return "my_default_identity"
        return identity

    def publish_card(self, username, previous_card_id=None):
        key_pair = self._crypto.generate_keys()
        return self.__get_manager().publish_card(
            identity=username,
            public_key=key_pair.public_key,
            private_key=key_pair.private_key,
            previous_card_id=previous_card_id,
            extra_fields={
                "some_meta_key": "some_meta_val"
            }
        )

    def get_card(self, card_id):
        return self.__get_manager().get_card(card_id)

    def search_card(self, identity):
        return self.__get_manager().search_card(identity)

    def sign_callback(self, model):
        response = self.__emulate_server_app_sign_response(model.to_string())
        return RawSignedModel.from_string(response)

    def __get_manager(self):

        validator = VirgilCardVerifier(CardCrypto())
        if config.VIRGIL_CARD_SERVICE_PUBLIC_KEY:
            validator._VirgilCardVerifier__virgil_public_key_base64 = config.VIRGIL_CARD_SERVICE_PUBLIC_KEY
        manager = CardManager(
            CardCrypto(),
            api_url=config.VIRGIL_API_URL,
            access_token_provider=CallbackJwtProvider(self._get_token_from_server),
            sign_callback=self.sign_callback,
            card_verifier=validator
        )
        return manager


