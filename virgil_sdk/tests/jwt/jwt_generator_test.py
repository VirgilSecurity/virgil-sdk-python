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
from virgil_sdk.utils import Utils
from virgil_crypto.access_token_signer import AccessTokenSigner

from virgil_crypto import VirgilCrypto

from virgil_sdk.tests import BaseTest
from virgil_sdk.tests import config


class JwtGeneratorTest(BaseTest):

    def test_generate_token_with_empty_identity(self):
        crypto = VirgilCrypto()
        key_file = open(config.VIRGIL_APP_KEY_PATH, "rb")
        raw_api_key_data = key_file.read()
        key_file.close()
        api_key = crypto.import_private_key(bytearray(Utils.b64decode(raw_api_key_data)))
        access_token_signer = AccessTokenSigner()

        jwt_generator = JwtGenerator(
            config.VIRGIL_APP_ID,
            api_key,
            config.VIRGIL_API_PUB_KEY_ID,
            10,
            access_token_signer
        )

        identity = "alice"
        token = jwt_generator.generate_token(identity)
        self.assertEqual(identity, token.identity)

        self.assertRaises(
            ValueError,
            jwt_generator.generate_token,
            None
        )
