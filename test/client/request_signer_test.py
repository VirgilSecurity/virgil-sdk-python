# Copyright (C) 2016-2017 Virgil Security Inc.
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
import io
import base64
import unittest
from test.client import config

from test.client.base_test import BaseTest
from virgil_sdk.client import RequestSigner
from virgil_sdk.client import Utils
from virgil_sdk.client.requests import CreateCardRequest
from virgil_sdk.client.requests import RevokeCardRequest
from virgil_sdk.cryptography import VirgilCrypto
from virgil_sdk.cryptography.hashes import Fingerprint

class RequestSignerTest(BaseTest):
    def __init__(self, *args, **kwargs):
        super(RequestSignerTest, self).__init__(*args, **kwargs)
        self.__request_signer = None

    def test_authority_sign_create_card_request(self):
        alice_keys = self._crypto.generate_keys()
        request = CreateCardRequest(
            identity="alice",
            identity_type="username",
            public_key=alice_keys.public_key.value,
        )
        self._request_signer.authority_sign(
            request,
            config.VIRGIL_APP_ID,
            self._app_private_key,
        )
        self.assertEqual(
            len(request.signatures),
            1,
        )
        self.assertEqual(
            list(request.signatures.keys())[0],
            config.VIRGIL_APP_ID
        )
        self._assertVerify(
            list(request.signatures.values())[0],
            request.snapshot,
            self._crypto.extract_public_key(self._app_private_key)
        )

    def test_authority_sign_revoke_card_request(self):
        request = RevokeCardRequest(
            card_id="some_card_id",
        )
        self._request_signer.authority_sign(
            request,
            config.VIRGIL_APP_ID,
            self._app_private_key,
        )
        self.assertEqual(
            len(request.signatures),
            1,
        )
        self.assertEqual(
            list(request.signatures.keys())[0],
            config.VIRGIL_APP_ID
        )
        self._assertVerify(
            list(request.signatures.values())[0],
            request.snapshot,
            self._crypto.extract_public_key(self._app_private_key)
        )

    def test_self_sign_create_card_request(self):
        alice_keys = self._crypto.generate_keys()
        request = CreateCardRequest(
            identity="alice",
            identity_type="username",
            public_key=alice_keys.public_key.value,
        )
        self._request_signer.self_sign(
            request,
            alice_keys.private_key
        )
        self.assertEqual(
            len(request.signatures),
            1,
        )
        self._assertVerify(
            list(request.signatures.values())[0],
            request.snapshot,
            alice_keys.public_key
        )

    def test_self_sign_revoke_card_request(self):
        alice_keys = self._crypto.generate_keys()
        request = RevokeCardRequest(
            card_id="some_card_id"
        )
        self._request_signer.self_sign(
            request,
            alice_keys.private_key
        )
        self.assertEqual(
            len(request.signatures),
            1,
        )
        self._assertVerify(
            list(request.signatures.values())[0],
            request.snapshot,
            alice_keys.public_key
        )

    def test_self_and_authority_sign_create_card_request(self):
        alice_keys = self._crypto.generate_keys()
        request = CreateCardRequest(
            identity="alice",
            identity_type="username",
            public_key=alice_keys.public_key.value,
        )
        self._request_signer.self_sign(
            request,
            alice_keys.private_key
        )
        self._request_signer.authority_sign(
            request,
            config.VIRGIL_APP_ID,
            self._app_private_key,
        )
        self.assertEqual(
            len(request.signatures),
            2,
        )
        authority_signature = request.signatures.pop(config.VIRGIL_APP_ID)
        self._assertVerify(
            authority_signature,
            request.snapshot,
            self._crypto.extract_public_key(self._app_private_key)
        )
        self._assertVerify(
            list(request.signatures.values())[0],
            request.snapshot,
            alice_keys.public_key
        )

    def test_self_and_authority_sign_revoke_card_request(self):
        alice_keys = self._crypto.generate_keys()
        request = RevokeCardRequest(
            card_id="some_card_id"
        )
        self._request_signer.self_sign(
            request,
            alice_keys.private_key
        )
        self._request_signer.authority_sign(
            request,
            config.VIRGIL_APP_ID,
            self._app_private_key,
        )
        self.assertEqual(
            len(request.signatures),
            2,
        )
        authority_signature = request.signatures.pop(config.VIRGIL_APP_ID)
        self._assertVerify(
            authority_signature,
            request.snapshot,
            self._crypto.extract_public_key(self._app_private_key)
        )
        self._assertVerify(
            list(request.signatures.values())[0],
            request.snapshot,
            alice_keys.public_key
        )

    def _assertVerify(self, signature, snapshot, public_key):
        decoded_signature = Utils.b64decode(signature)
        fingerprint = self._crypto.calculate_fingerprint(
            snapshot
        )
        verified = self._crypto.verify(
            fingerprint.value,
            bytearray(decoded_signature),
            public_key
        )
        self.assertTrue(verified)

    @property
    def _request_signer(self):
        if self.__request_signer:
            return self.__request_signer

        self.__request_signer = RequestSigner(self._crypto)
        return self.__request_signer
