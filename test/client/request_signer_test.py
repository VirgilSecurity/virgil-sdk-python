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
