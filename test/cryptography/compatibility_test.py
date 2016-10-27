# Copyright (C) 2016 Virgil Security Inc.
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
import json
import unittest
import base64

from virgil_sdk.cryptography import VirgilCrypto

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
            "..",
            "data",
            "sdk_compatibility_data.json"
        )
        self.__compatibility_data_path = data_file_path
        return data_file_path
