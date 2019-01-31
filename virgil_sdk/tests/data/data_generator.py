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
import os

from virgil_crypto.card_crypto import CardCrypto

from virgil_sdk.tests import config
from virgil_sdk import CardManager, VirgilCardVerifier
from virgil_sdk.cards import RawCardContent
from virgil_sdk.client import RawSignedModel
from virgil_sdk.jwt import JwtGenerator
from virgil_sdk.jwt.abstractions import AccessTokenProvider
from virgil_sdk.signers import ModelSigner


class DataGenerator(object):

    def __init__(self, crypto):
        self._crypto = crypto

    def generate_empty_access_token_provider(self):

        class EmptyAccessTokenProvider(AccessTokenProvider):

            def get_token(self, token_context):
                pass

        return EmptyAccessTokenProvider()

    def generate_key_pair(self):
        return self._crypto.generate_keys()

    def generate_card_id(self):
        return self.generate_app_id()

    @staticmethod
    def generate_app_id():
        return str(binascii.hexlify(os.urandom(32)).decode())

    def generate_raw_signed_model(
            self,
            key_pair,
            add_self_sign=False,
            virgil_key_pair=None,
            extra_key_pair=None,
            previous_card_id=None
    ):
        create_time = 1515686245
        raw_card_content = RawCardContent(
            created_at=create_time,
            identity="test",
            public_key=key_pair.public_key,
            version="5.0",
            previous_card_id=previous_card_id
        )
        model = RawSignedModel(raw_card_content.content_snapshot)
        signer = ModelSigner(CardCrypto())

        if add_self_sign:
            signer.self_sign(model, key_pair.private_key)

        if virgil_key_pair:
            signer.sign(model, ModelSigner.VIRGIL_SIGNER, virgil_key_pair.private_key)

        if extra_key_pair:
            signer.sign(model, "extra", extra_key_pair.private_key)

        return model

    def generate_card_manager(self, token_provider=None):
        if not token_provider:
            token_provider = self.generate_empty_access_token_provider()
        return CardManager(
            CardCrypto(),
            token_provider,
            VirgilCardVerifier(CardCrypto(), False, False)
        )

    def generate_token(self, private_key, signer, token_ttl):
        api_public_key_id = config.VIRGIL_API_PUB_KEY_ID
        app_id = config.VIRGIL_APP_ID

        jwt_generator = JwtGenerator(
            app_id,
            private_key,
            api_public_key_id,
            token_ttl,
            signer
        )

        additional_data = {"username": "some_username"}
        token = jwt_generator.generate_token("some_identity", additional_data)
        return token
