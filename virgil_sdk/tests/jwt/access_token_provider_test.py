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
import time

from virgil_crypto.access_token_signer import AccessTokenSigner
from virgil_sdk.tests import config

from virgil_sdk.tests.base_test import BaseTest
from virgil_sdk.jwt import TokenContext, JwtGenerator
from virgil_sdk.jwt.providers import CachingCallbackProvider


class CachingJwtProviderTest(BaseTest):

    def __init__(self, *args, **kwargs):
        super(CachingJwtProviderTest, self).__init__(*args, **kwargs)
        self.renew_callback_counter = 0


    def test_return_valid_token(self):
        # STC-38
        provider = CachingCallbackProvider(self._get_token_from_server, 10)
        jwt = provider.get_token(TokenContext("some_identity", "some_operation"))
        jwt2 = provider.get_token(TokenContext("some_identity", "some_operation"))
        self.assertEqual(jwt, jwt2)

    def test_return_new_token_when_expired(self):
        # STC-38
        provider = CachingCallbackProvider(self._get_token_from_server, 1)
        jwt = provider.get_token(TokenContext("some_identity", "some_operation"))
        time.sleep(2)
        jwt2 = provider.get_token(TokenContext("some_identity", "some_operation"))
        self.assertNotEqual(jwt, jwt2)

    def test_token_expiration_ttl(self):
        # STC-40
        key_pair = self._crypto.generate_keys()
        jwt_generator = JwtGenerator(
            config.VIRGIL_APP_ID,
            key_pair.private_key,
            config.VIRGIL_API_PUB_KEY_ID,
            10,
            AccessTokenSigner()
        )
        initial_token = jwt_generator.generate_token("initialJwt")
        provider = CachingCallbackProvider(self.renew_jwt_callback, initial_token=initial_token, token_ttl=10)
        self.renew_callback_counter = 0
        context = TokenContext(identity="initialJwt", operation="test")
        token_1 = provider.get_token(context)
        time.sleep(3)
        token_2 = provider.get_token(context)
        time.sleep(9)
        token_3 = provider.get_token(context)
        self.assertEqual(initial_token, token_1)
        self.assertEqual(initial_token, token_2)
        self.assertNotEqual(initial_token, token_3)
        self.assertEqual(1, self.renew_callback_counter)
        self.renew_callback_counter = 0

    def renew_jwt_callback(self, token_context, token_ttl):
        builder = JwtGenerator(
            config.VIRGIL_APP_ID,
            self._app_private_key,
            config.VIRGIL_API_PUB_KEY_ID,
            token_ttl,
            AccessTokenSigner()
        )
        self.renew_callback_counter += 1
        return builder.generate_token(token_context.identity).to_string()

    def test_jwt_caching_provider_force_reload(self):
        # STC-43

        identity = "alice"
        token_ttl = 10

        builder = JwtGenerator(
            config.VIRGIL_APP_ID,
            self._app_private_key,
            config.VIRGIL_API_PUB_KEY_ID,
            token_ttl,
            AccessTokenSigner()
        )

        token_context_1 = TokenContext(identity, "test", force_reload=False)
        token_context_2 = TokenContext(identity, "test", force_reload=True)

        initial_token = builder.generate_token(identity)

        jwt_provider = CachingCallbackProvider(self.renew_jwt_callback, token_ttl, initial_token=initial_token)

        jwt_from_context_1 = jwt_provider.get_token(token_context_1)
        jwt_from_context_2 = jwt_provider.get_token(token_context_2)

        self.assertEqual(jwt_from_context_1, initial_token)
        self.assertNotEqual(jwt_from_context_2, initial_token)
        self.assertNotEqual(jwt_from_context_1, jwt_from_context_2)
