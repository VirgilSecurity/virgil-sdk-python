import io
import os
import json
import unittest
import base64

from virgil_sdk.cryptography import crypto
from virgil_sdk.cryptography.crypto import VirgilCrypto

try:
    basestring
except NameError:
    basestring=str


class CompatibilityTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(CompatibilityTest, self).__init__(*args, **kwargs)
        self.__compatibility_data_path = None
        self.__compatibility_data = None
        self.__crypto = None

    def test_encrypt_single_recipient(self):
        data = self._compatibility_data["encrypt_single_recipient"]
        private_key = self._crypto.import_private_key(data["private_key"])
        decrypted_data = self._crypto.decrypt(data["cipher_data"], private_key)
        self.assertEqual(data["original_data"], decrypted_data)

    def test_encrypt_multiple_recipients(self):
        data = self._compatibility_data["encrypt_multiple_recipients"]
        private_keys = [self._crypto.import_private_key(pk) for pk in data["private_keys"]]
        for private_key in private_keys:
            decrypted_data = self._crypto.decrypt(data["cipher_data"], private_key)
            self.assertEqual(data["original_data"], decrypted_data)

    def test_sign_then_encrypt_single_recipient(self):
        data = self._compatibility_data["sign_then_encrypt_single_recipient"]
        private_key = self._crypto.import_private_key(data["private_key"])
        public_key = self._crypto.extract_public_key(private_key)
        decrypted_data = self._crypto.decrypt_then_verify(
            data["cipher_data"],
            private_key,
            public_key
        )
        self.assertEqual(data["original_data"], decrypted_data)

    def test_sign_then_encrypt_multiple_recipients(self):
        data = self._compatibility_data["sign_then_encrypt_multiple_recipients"]
        private_keys = [self._crypto.import_private_key(pk) for pk in data["private_keys"]]
        public_key = self._crypto.extract_public_key(private_keys[0])
        for private_key in private_keys:
            decrypted_data = self._crypto.decrypt_then_verify(
                data["cipher_data"],
                private_key,
                public_key
            )
            self.assertEqual(data["original_data"], decrypted_data)

    def test_generate_signature(self):
        data = self._compatibility_data["generate_signature"]
        private_key = self._crypto.import_private_key(data["private_key"])
        signature = self._crypto.sign(data["original_data"], private_key)
        self.assertEqual(data["signature"], signature)
        public_key = self._crypto.extract_public_key(private_key)
        self.assertTrue(
            self._crypto.verify(data["original_data"], data["signature"], public_key)
        )

    @property
    def _crypto(self):
        if self.__crypto:
            return self.__crypto
        self.__crypto = VirgilCrypto()
        return self.__crypto

    @property
    def _compatibility_data(self):
        if self.__compatibility_data:
            return self.__compatibility_data
        with open(self._compatibility_data_path, "r") as data_file:
            raw_data = data_file.read()

        json_data = json.loads(raw_data)
        self.__compatibility_data = self._decode_data(json_data)
        return self.__compatibility_data

    def _decode_data(self, data):
        if isinstance(data, dict):
            return {k: self._decode_data(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._decode_data(v) for v in data]
        elif isinstance(data, basestring):
            return tuple(bytearray(base64.b64decode(bytearray(data, "utf-8"))))
        else:
            return data

    @property
    def _compatibility_data_path(self):
        if self.__compatibility_data_path:
            return self.__compatibility_data_path
        this_file_path = os.path.abspath(__file__)
        cwd = os.path.dirname(this_file_path)
        data_file_path = os.path.join(
            cwd,
            "data",
            "sdk_compatibility_data.json"
        )
        self.__compatibility_data_path = data_file_path
        return data_file_path
