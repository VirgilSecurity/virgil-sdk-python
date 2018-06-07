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
import datetime
import os
from base64 import b64encode

from virgil_crypto.access_token_signer import AccessTokenSigner
from virgil_crypto.card_crypto import CardCrypto

from tests import config
from tests.base_test import BaseTest
from virgil_sdk.client.connections.urllib import urllib2
from virgil_sdk.cards import RawCardContent
from virgil_sdk.client import CardClient, RawSignedModel
from virgil_sdk.jwt import JwtGenerator
from virgil_sdk.signers import ModelSigner


class CardClientTest(BaseTest):

    def test_publish_card_with_wrong_key(self):
        # STC-25
        identity = b64encode(os.urandom(15)).decode()
        jwt = self.__jwt_signed_wrong_key(identity)
        client = CardClient()
        self.assertRaises(
            urllib2.HTTPError,
            client.publish_card,
            self.__generate_raw_signed_model(identity),
            jwt.to_string()
        )

    def test_get_card_with_wrong_key(self):
        # STC-25
        jwt = self.__jwt_signed_wrong_key(b64encode(os.urandom(15)).decode())
        client = CardClient()
        self.assertRaises(
            urllib2.HTTPError,
            client.get_card,
            self._data_generator.generate_card_id(),
            jwt.to_string()
        )

    def test_search_card_with_wrong_key(self):
        # STC-25
        jwt = self.__jwt_signed_wrong_key(b64encode(os.urandom(15)).decode())
        client = CardClient()
        self.assertRaises(
            urllib2.HTTPError,
            client.search_card,
            b64encode(os.urandom(15)).decode(),
            jwt.to_string()
        )

    def test_publish_card_with_wrong_token_identity(self):
        # STC-27
        jwt = self.__generate_jwt(
            b64encode(os.urandom(15)).decode(),
            self._app_private_key,
            config.VIRGIL_API_KEY_ID
        )
        client = CardClient()
        self.assertRaises(
            urllib2.HTTPError,
            client.publish_card,
            self.__generate_raw_signed_model(b64encode(os.urandom(15)).decode()),
            jwt.to_string()
        )

    def __jwt_signed_wrong_key(self, identity):
        wrong_api_key_pair = self._crypto.generate_keys()
        wrong_api_key_id = self._data_generator.generate_app_id()
        return self.__generate_jwt(identity, wrong_api_key_pair.private_key, wrong_api_key_id)

    def __generate_raw_signed_model(self, identity):
        key_pair = self._crypto.generate_keys()
        raw_card_content = RawCardContent(
            created_at=datetime.datetime.utcnow().timestamp(),
            identity=identity,
            public_key=key_pair.public_key,
            version="5.0"
        )
        model = RawSignedModel(raw_card_content.content_snapshot)
        signer = ModelSigner(CardCrypto())
        signer.self_sign(model, key_pair.private_key)
        return model

    def __generate_jwt(self, identity, api_private_key, api_public_key_id):
        jwt_generator = JwtGenerator(
            config.VIRGIL_APP_ID,
            api_private_key,
            api_public_key_id,
            datetime.timedelta(minutes=10).seconds,
            AccessTokenSigner()
        )
        return jwt_generator.generate_token(identity)