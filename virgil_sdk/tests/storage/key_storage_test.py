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
import binascii
import hashlib
import os

from virgil_sdk.storage import KeyStorage
from virgil_sdk.storage.key_entry import KeyEntry

from virgil_sdk.tests import BaseTest


class KeyStorageTest(BaseTest):

    def test_store(self):
        # STC-5, STC-6
        key_name = "test_key-{}".format(str(binascii.hexlify(os.urandom(5)).decode()))
        key_pair = self._crypto.generate_keys()
        key_entry = KeyEntry(
            key_name,
            key_pair.private_key.raw_key,
            {}
        )
        key_storage = KeyStorage()
        key_storage.store(key_entry)
        file_path = self.__filename_for_clean(key_storage, key_name)
        try:
            self.assertTrue(os.path.exists(file_path))
        finally:
            os.remove(file_path)

    def test_store_none(self):
        # STC-5, STC-6
        key_entry = None
        key_storage = KeyStorage()
        self.assertRaises(ValueError, key_storage.store, key_entry)

    def test_load(self):
        # STC-5, STC-6
        key_name = "test_key-{}".format(str(binascii.hexlify(os.urandom(5)).decode()))
        additional_data = {"some_key": "some_value"}
        key_pair = self._crypto.generate_keys()
        key_entry = KeyEntry(
            key_name,
            key_pair.private_key.raw_key,
            additional_data
        )
        key_storage = KeyStorage()
        key_storage.store(key_entry)
        raw_loaded_key_entry = key_storage.load(key_name)
        try:
            self.assertEqual(raw_loaded_key_entry["name"], key_name)
            self.assertEqual(bytearray(key_pair.private_key.raw_key), bytearray(raw_loaded_key_entry["value"]))
            self.assertDictEqual(additional_data, raw_loaded_key_entry["meta"])
        finally:
            os.remove(self.__filename_for_clean(key_storage, key_name))

    def test_load_unexisting_key(self):
        # STC-5, STC-6
        key_name = "test_key-{}".format(str(binascii.hexlify(os.urandom(10)).decode()))
        key_storage = KeyStorage()
        self.assertRaises(ValueError, key_storage.load, key_name)

    def test_load_key_with_empty_name(self):
        # STC-5, STC-6
        key_storage = KeyStorage()
        self.assertRaises(ValueError, key_storage.load, None)

    def test_delete(self):
        # STC-5, STC-6
        key_name = "test_key-{}".format(str(binascii.hexlify(os.urandom(5)).decode()))
        key_pair = self._crypto.generate_keys()
        key_entry = KeyEntry(
            key_name,
            key_pair.private_key.raw_key,
            {}
        )
        key_storage = KeyStorage()
        key_storage.store(key_entry)
        key_storage.delete(key_name)
        file_path = self.__filename_for_clean(key_storage, key_name)
        try:
            self.assertRaises(ValueError, key_storage.load, key_name)
            self.assertFalse(os.path.exists(file_path))
        finally:
            if os.path.exists(file_path):
                os.remove(file_path)

    def test_delete_unexisting_key(self):
        # STC-5, STC-6
        key_name = "test_key-{}".format(str(binascii.hexlify(os.urandom(10)).decode()))
        key_storage = KeyStorage()
        self.assertRaises(ValueError, key_storage.delete, key_name)

    def test_delete_key_empty_name(self):
        # STC-5, STC-6
        key_storage = KeyStorage()
        self.assertRaises(ValueError, key_storage.delete, None)

    def __filename_for_clean(self, key_storage, key_name):
        file_name = hashlib.sha384(key_name.encode("utf-8")).hexdigest()
        return os.path.join(key_storage._KeyStorage__key_storage_path, file_name)
