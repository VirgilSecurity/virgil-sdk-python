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
from virgil_sdk.tests import config
from virgil_sdk.tests import BaseTest

from virgil_crypto.access_token_signer import AccessTokenSigner
from virgil_sdk.jwt import Jwt, JwtVerifier
from virgil_sdk.utils import Utils


class JwtVerifierTest(BaseTest):

    def test_verify_imported_token(self):
        # STC-22
        private_key = self._app_private_key
        public_key = self._crypto.extract_public_key(private_key)

        signer = AccessTokenSigner()
        jwt = self._data_generator.generate_token(private_key, signer, 300)
        exported_token = jwt.to_string()
        imported_token = Jwt.from_string(exported_token)
        verifier = JwtVerifier(
            signer,
            public_key,
            config.VIRGIL_API_KEY_ID
        )
        self.assertTrue(verifier.verify_token(jwt))
        self.assertTrue(verifier.verify_token(imported_token))

    def test_verify_created_in_another_sdk(self):
        # STC-22
        token_base64 = self._compatibility_data["STC-22.jwt"]
        public_key_base64 = self._compatibility_data["STC-22.api_public_key_base64"]
        key_id_base64 = self._compatibility_data["STC-22.api_key_id"]

        jwt = Jwt.from_string(token_base64)
        exported_token = jwt.to_string()
        signer = AccessTokenSigner()
        verifier = JwtVerifier(
            signer,
            self._crypto.import_public_key(Utils.strtobytes(Utils.b64decode(public_key_base64))),
            key_id_base64
        )
        self.assertEqual(exported_token, token_base64)
        self.assertTrue(verifier.verify_token(jwt))
