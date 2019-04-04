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
from virgil_sdk.jwt import JwtGenerator
from virgil_sdk.jwt import TokenContext
from virgil_sdk.jwt import Jwt
from virgil_sdk.jwt.providers import GeneratorJwtProvider
from virgil_sdk.tests import BaseTest
from virgil_sdk.tests import config
from virgil_sdk.utils import Utils

from virgil_crypto import VirgilCrypto
from virgil_crypto.access_token_signer import AccessTokenSigner


class GeneratorJwtProviderTest(BaseTest):

    def test_get_new_token(self):
        crypto = VirgilCrypto()
        key_file = open(config.VIRGIL_APP_KEY_PATH, "rb")
        raw_api_key_data = key_file.read()
        key_file.close()
        api_key = crypto.import_private_key(bytearray(bytearray(Utils.b64decode(raw_api_key_data))))
        access_token_signer = AccessTokenSigner()
        identity = "alice"
        action = "test"
        default_identity = "default"
        default_additional_data = {"some_field": "some_data"}

        jwt_generator = JwtGenerator(
            config.VIRGIL_APP_ID,
            api_key,
            config.VIRGIL_API_PUB_KEY_ID,
            10,
            access_token_signer
        )

        jwt_provider = GeneratorJwtProvider(jwt_generator, default_identity)
        jwt_provider_with_data = GeneratorJwtProvider(jwt_generator, default_identity, default_additional_data)

        token_context = TokenContext(identity, action)
        token_context_without_identity = TokenContext(None, action)

        token_1 = jwt_provider.get_token(token_context)
        token_2 = jwt_provider.get_token(token_context_without_identity)

        self.assertIsNotNone(token_1)
        self.assertFalse(token_1.is_expired())
        self.assertEqual(identity, token_1.identity)

        self.assertIsNotNone(token_2)
        self.assertFalse(token_2.is_expired())
        self.assertEqual(default_identity, token_2.identity)

        self.assertNotEqual(token_1, token_2)
        self.assertNotEqual(token_1.identity, token_2.identity)

        token_3 = jwt_provider_with_data.get_token(token_context)
        token_4 = jwt_provider_with_data.get_token(token_context_without_identity)

        self.assertEqual(identity, token_3.identity)
        self.assertEqual(default_additional_data, token_3.body_content.additional_data)

        self.assertEqual(default_identity, token_4.identity)
        self.assertEqual(default_additional_data, token_4.body_content.additional_data)

        self.assertIsNotNone(token_3)
        self.assertIsNotNone(token_4)
        self.assertNotEqual(token_3, token_4)
