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

from virgil_sdk.storage import PrivateKeyExporter
from virgil_sdk.storage import PrivateKeyStorage
from virgil_sdk.tests import BaseTest


class PrivateKeyStorageTest(BaseTest):

    def test_store(self):
        # STC-7
        key_name = "test_key-{}".format(str(binascii.hexlify(os.urandom(5)).decode()))
        key_pair = self._crypto.generate_keys()
        private_key_exporter = PrivateKeyExporter(self._crypto)
        private_key_storage = PrivateKeyStorage(private_key_exporter)
        private_key_storage.store(key_pair.private_key, key_name)
        try:
            self.assertTrue(os.path.exists(self.__filename_for_clean(private_key_storage, key_name)))
        finally:
            os.remove(self.__filename_for_clean(private_key_storage, key_name))

    def test_store_empty_name(self):
        # STC-7
        key_pair = self._crypto.generate_keys()
        private_key_exporter = PrivateKeyExporter(self._crypto)
        private_key_storage = PrivateKeyStorage(private_key_exporter)
        self.assertRaises(ValueError, private_key_storage.store, key_pair.private_key, None)

    def test_store_empty_key(self):
        # STC-7
        key_name = "test_key-{}".format(str(binascii.hexlify(os.urandom(5)).decode()))
        private_key_exporter = PrivateKeyExporter(self._crypto)
        private_key_storage = PrivateKeyStorage(private_key_exporter)
        self.assertRaises(ValueError, private_key_storage.store, None, key_name)

    def test_load(self):
        # STC-7
        key_name = "test_key-{}".format(str(binascii.hexlify(os.urandom(5)).decode()))
        key_pair = self._crypto.generate_keys()
        additional_data = {"some_key": "some_val"}
        private_key_exporter = PrivateKeyExporter(self._crypto)
        private_key_storage = PrivateKeyStorage(private_key_exporter)
        private_key_storage.store(key_pair.private_key, key_name, additional_data)
        loaded_key, loaded_meta = private_key_storage.load(key_name)
        try:
            self.assertEqual(loaded_key, key_pair.private_key)
            self.assertEqual(loaded_meta, additional_data)
        finally:
            os.remove(self.__filename_for_clean(private_key_storage, key_name))

    def test_load_unexisting_key(self):
        # STC-7
        key_name = "test_key-{}".format(str(binascii.hexlify(os.urandom(10)).decode()))
        private_key_exporter = PrivateKeyExporter(self._crypto)
        private_key_storage = PrivateKeyStorage(private_key_exporter)
        self.assertRaises(ValueError, private_key_storage.load, key_name)

    def test_delete(self):
        # STC-7
        key_name = "test_key-{}".format(str(binascii.hexlify(os.urandom(5)).decode()))
        key_pair = self._crypto.generate_keys()
        private_key_exporter = PrivateKeyExporter(self._crypto)
        private_key_storage = PrivateKeyStorage(private_key_exporter)
        private_key_storage.store(key_pair.private_key, key_name)
        try:
            private_key_storage.delete(key_name)
            self.assertFalse(os.path.exists(self.__filename_for_clean(private_key_storage, key_name)))
        finally:
            if os.path.exists(self.__filename_for_clean(private_key_storage, key_name)):
                os.remove(self.__filename_for_clean(private_key_storage, key_name))

    def test_delete_unexisting_key(self):
        # STC-7
        key_name = "test_key-{}".format(str(binascii.hexlify(os.urandom(10)).decode()))
        private_key_exporter = PrivateKeyExporter(self._crypto)
        private_key_storage = PrivateKeyStorage(private_key_exporter)
        self.assertRaises(ValueError, private_key_storage.delete, key_name)

    def test_delete_empty_name(self):
        # STC-7
        private_key_exporter = PrivateKeyExporter(self._crypto)
        private_key_storage = PrivateKeyStorage(private_key_exporter)
        self.assertRaises(ValueError, private_key_storage.delete, None)

    def __filename_for_clean(self, private_key_storage, key_name):
        file_name = hashlib.sha384(key_name.encode("utf-8")).hexdigest()
        return os.path.join(private_key_storage.key_storage._KeyStorage__key_storage_path, file_name)
