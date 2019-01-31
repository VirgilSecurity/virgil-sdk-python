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
import os
from time import sleep

from virgil_sdk.tests import BaseTest
from virgil_sdk.jwt import TokenContext, Jwt
from virgil_sdk.jwt.providers import CallbackJwtProvider, ConstAccessTokenProvider
from virgil_sdk.utils import Utils


class AccessTokenProviderTest(BaseTest):

    def test_get_token_from_server(self):
        # STC-24
        call_back_provider = CallbackJwtProvider(self._get_token_from_server)
        context = TokenContext("test_identity", "some_operation")
        token1 = call_back_provider.get_token(context)
        sleep(1)
        token2 = call_back_provider.get_token(context)
        self.assertNotEqual(token1.to_string(), token2.to_string())
        self.assertNotEqual(token1, token2)

    def test_get_invalid_token_from_server(self):
        # STC-24
        def failed_get_from_server(context):
            return Utils.b64encode(os.urandom(30))

        callback_provider = CallbackJwtProvider(failed_get_from_server)
        context = TokenContext("test_identity", "some_operation")
        self.assertRaises(ValueError, callback_provider.get_token, context)

    def test_get_const_access_token(self):
        # STC-37
        token_from_server = self._get_token_from_server(
            TokenContext(
                Utils.b64encode(os.urandom(20)),
                "some_operation"
            )
        )
        jwt = Jwt.from_string(token_from_server)
        const_token_provider = ConstAccessTokenProvider(jwt)
        token1 = const_token_provider.get_token(
            TokenContext(
                Utils.b64encode(os.urandom(10)),
                Utils.b64encode(os.urandom(10)),
                True
            )
        )

        token2 = const_token_provider.get_token(
            TokenContext(
                Utils.b64encode(os.urandom(10)),
                Utils.b64encode(os.urandom(10)),
                True
            )
        )
        self.assertEqual(token1, token2)

    def test_imported_token_compare_with_origin(self):
        callback_provider = CallbackJwtProvider(self._get_token_from_server)
        context = TokenContext(
            Utils.b64encode(os.urandom(20)),
            "some_operation"
        )
        token = callback_provider.get_token(context)
        imported_token = Jwt.from_string(token.to_string())
        self.assertTrue(token, imported_token)

