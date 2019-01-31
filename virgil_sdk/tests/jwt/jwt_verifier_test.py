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
from virgil_sdk.tests import config
from virgil_sdk.tests import BaseTest

from virgil_crypto.access_token_signer import AccessTokenSigner
from virgil_sdk.jwt import Jwt, JwtVerifier, JwtGenerator
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
            config.VIRGIL_API_PUB_KEY_ID
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

    def test_verify_generated_jwt(self):
        # STC-23
        public_key_base64 = self._compatibility_data["STC-23.api_public_key_base64"]
        private_key_base64 = self._compatibility_data["STC-23.api_private_key_base64"]
        private_key = self._crypto.import_private_key(Utils.strtobytes(Utils.b64decode(private_key_base64)))
        public_key = self._crypto.import_public_key(Utils.strtobytes(Utils.b64decode(public_key_base64)))
        key_id_base64 = self._compatibility_data["STC-23.api_key_id"]
        signer = AccessTokenSigner()

        jwt_generator = JwtGenerator(
            self._compatibility_data["STC-23.app_id"],
            private_key,
            key_id_base64,
            10,
            signer
        )
        token = jwt_generator.generate_token("some_identity", data={"username": "some_username"})
        verifier = JwtVerifier(
            signer,
            public_key,
            key_id_base64
        )
        self.assertFalse(token.is_expired())
        self.assertTrue(verifier.verify_token(token))

    def test_verify_imported_compatibility_jwt(self):
        # STC-28
        token_base64 = self._compatibility_data["STC-28.jwt"]
        jwt = Jwt.from_string(token_base64)
        self.assertEqual(self._compatibility_data["STC-28.jwt_identity"], jwt.body_content.identity)
        self.assertEqual(self._compatibility_data["STC-28.jwt_app_id"], jwt.body_content.app_id)
        self.assertEqual(self._compatibility_data["STC-28.jw_issuer"], jwt.body_content.issuer)
        self.assertEqual(self._compatibility_data["STC-28.jwt_subject"], jwt.body_content.subject)
        self.assertEqual(
            Utils.json_loads(self._compatibility_data["STC-28.jwt_additional_data"]),
            jwt.body_content.additional_data
        )
        self.assertEqual(
            int(self._compatibility_data["STC-28.jwt_expires_at"]),
            jwt.body_content.expires_at_timestamp
        )
        self.assertEqual(
            int(self._compatibility_data["STC-28.jwt_issued_at"]),
            jwt.body_content.issued_at_timestamp
        )
        self.assertEqual(self._compatibility_data["STC-28.jwt_algorithm"], jwt.header_content.algorithm)
        self.assertEqual(self._compatibility_data["STC-28.jwt_api_key_id"], jwt.header_content.key_id)
        self.assertEqual(self._compatibility_data["STC-28.jwt_content_type"], jwt.header_content.content_type)
        self.assertEqual(self._compatibility_data["STC-28.jwt_type"], jwt.header_content.access_token_type)
        self.assertEqual(
            Utils.b64decode(self._compatibility_data["STC-28.jwt_signature_base64"]),
            jwt.signature_data
        )
        self.assertTrue(jwt.is_expired())
        self.assertEqual(token_base64, jwt.to_string())

    def test_verify_imported_compatibility_jwt_not_expired(self):
        # STC-29
        token_base64 = self._compatibility_data["STC-29.jwt"]
        jwt = Jwt.from_string(token_base64)
        self.assertEqual(self._compatibility_data["STC-29.jwt_identity"], jwt.body_content.identity)
        self.assertEqual(self._compatibility_data["STC-29.jwt_app_id"], jwt.body_content.app_id)
        self.assertEqual(self._compatibility_data["STC-29.jw_issuer"], jwt.body_content.issuer)
        self.assertEqual(self._compatibility_data["STC-29.jwt_subject"], jwt.body_content.subject)
        self.assertEqual(
            Utils.json_loads(self._compatibility_data["STC-29.jwt_additional_data"]),
            jwt.body_content.additional_data
        )
        self.assertEqual(
            int(self._compatibility_data["STC-29.jwt_expires_at"]),
            jwt.body_content.expires_at_timestamp
        )
        self.assertEqual(
            int(self._compatibility_data["STC-29.jwt_issued_at"]),
            jwt.body_content.issued_at_timestamp
        )
        self.assertEqual(self._compatibility_data["STC-29.jwt_algorithm"], jwt.header_content.algorithm)
        self.assertEqual(self._compatibility_data["STC-29.jwt_api_key_id"], jwt.header_content.key_id)
        self.assertEqual(self._compatibility_data["STC-29.jwt_content_type"], jwt.header_content.content_type)
        self.assertEqual(self._compatibility_data["STC-29.jwt_type"], jwt.header_content.access_token_type)
        self.assertEqual(
            Utils.b64decode(self._compatibility_data["STC-29.jwt_signature_base64"]),
            jwt.signature_data
        )
        self.assertFalse(jwt.is_expired())
        self.assertEqual(token_base64, jwt.to_string())

    def test_generate_token_with_wrong_additional_data_type(self):
        key_pair = self._crypto.generate_keys()
        api_public_key_id = config.VIRGIL_API_PUB_KEY_ID
        app_id = config.VIRGIL_APP_ID
        signer = AccessTokenSigner()

        jwt_generator = JwtGenerator(
            app_id,
            key_pair.private_key,
            api_public_key_id,
            60,
            signer
        )
        # try init with string
        self.assertRaises(
            TypeError,
            jwt_generator.generate_token,
            "some_username",
            "some text"

        )
        self.assertRaises(
            TypeError,
            jwt_generator.generate_token,
            "some_username",
            ["some text", "another text"]
        )
        self.assertRaises(
            TypeError,
            jwt_generator.generate_token,
            "some_username",
            ("some text", "another text")
        )

    def test_generate_token_with_empty_data(self):
        key_pair = self._crypto.generate_keys()
        api_public_key_id = config.VIRGIL_API_PUB_KEY_ID
        app_id = config.VIRGIL_APP_ID
        signer = AccessTokenSigner()

        jwt_generator = JwtGenerator(
            app_id,
            key_pair.private_key,
            api_public_key_id,
            60,
            signer
        )
        token = jwt_generator.generate_token(identity="some_username")
        self.assertFalse(token.is_expired())
