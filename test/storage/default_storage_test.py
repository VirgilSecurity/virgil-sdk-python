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

import hashlib
import os
import unittest
from virgil_sdk.cryptography.crypto import VirgilCrypto
from virgil_sdk.storage.default_key_storage import DefaultKeyStorage


class DefaultStorageTest(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(DefaultStorageTest, self).__init__(*args, **kwargs)
        self.__crypto = VirgilCrypto()
        self.__key_pair = self.__crypto.generate_keys()

    def __secure_alias(self, alias):
        return hashlib.sha384(alias.encode("utf-8")).hexdigest()

    def test_store(self):
        alias = "test_store_key_name"
        path_to_key = os.path.join(os.getenv("HOME"), ".virgil/{}".format(self.__secure_alias(alias)))
        key_value = bytes(self.__crypto.export_private_key(self.__key_pair.private_key))
        key_storage = DefaultKeyStorage()
        try:
            key_storage.store(alias, key_value)
            self.assertTrue(os.path.exists(path_to_key))
            self.assertIsNotNone(open(path_to_key, "rb").read())
        finally:
            if os.path.exists(path_to_key):
                os.remove(path_to_key)

    def test_store_with_same_name(self):
        alias = "test_store_key_name"
        path_to_key = os.path.join(os.getenv("HOME"), ".virgil/{}".format(self.__secure_alias(alias)))
        key_value = bytes(self.__crypto.export_private_key(self.__key_pair.private_key))
        key_storage = DefaultKeyStorage()
        try:
            key_storage.store(alias, key_value)
            with self.assertRaises(Exception) as context:
                key_storage.store(alias, key_value)
            self.assertTrue("Can't store key " in str(context.exception))
        finally:
            if os.path.exists(path_to_key):
                os.remove(path_to_key)

    def test_load(self):
        alias = "test_load_key_name"
        path_to_key = os.path.join(os.getenv("HOME"), ".virgil/{}".format(self.__secure_alias(alias)))
        key_value = bytes(self.__crypto.export_private_key(self.__key_pair.private_key))
        key_storage = DefaultKeyStorage()
        try:
            key_storage.store(alias, key_value)
            self.assertEqual(type(key_storage.load(alias)), bytes)
            self.assertEqual(key_storage.load(alias), bytes(self.__key_pair.private_key.value))
        finally:
            if os.path.exists(path_to_key):
                os.remove(path_to_key)

    def test_load_non_existent_key(self):
        alias = "test_load_non_existent_key"
        key_storage = DefaultKeyStorage()
        with self.assertRaises(Exception) as context:
            key_storage.load(alias)
        self.assertTrue("Can't load key " in str(context.exception))

    def test_delete(self):
        alias = "test_delete_key_name"
        path_to_key = os.path.join(os.getenv("HOME"), ".virgil/{}".format(self.__secure_alias(alias)))
        key_value = bytes(self.__crypto.export_private_key(self.__key_pair.private_key))
        key_storage = DefaultKeyStorage()
        try:
            key_storage.store(alias, key_value)
            self.assertTrue(os.path.exists(path_to_key))
            key_storage.delete(alias)
            self.assertFalse(os.path.exists(path_to_key))
        finally:
            if os.path.exists(path_to_key):
                os.remove(path_to_key)

    def test_delete_non_existent_key(self):
        alias = "test_delete_non_existent_key_key_name"
        key_storage = DefaultKeyStorage()
        with self.assertRaises(Exception) as context:
            key_storage.delete(alias)
        self.assertTrue("Can't delete key" in str(context.exception))
