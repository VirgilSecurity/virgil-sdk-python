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
import unittest

from test.client import config
from virgil_sdk.api import Credentials
from virgil_sdk.api import VirgilBuffer
from virgil_sdk.api import VirgilContext
from virgil_sdk.api import VirgilKey
from virgil_sdk.api import KeyManager
from virgil_sdk.storage import DefaultKeyStorage


class KeyManagerTest(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(KeyManagerTest, self).__init__(*args, **kwargs)
        self._context = None

    def test_generate(self):
        km = KeyManager(self.__context)
        self.assertIsInstance(km.generate(), VirgilKey)

    def test_load(self):
        km = KeyManager(self.__context)
        key_pair = self.__context.crypto.generate_keys()
        vk = VirgilKey(self.__context, key_pair.private_key)
        alias = "key_manager_test_load"
        try:
            vk.save(alias)
            self.assertEqual(vk._VirgilKey__private_key, km.load(alias)._VirgilKey__private_key)
        finally:
            try:
                ks = DefaultKeyStorage()
                ks.delete(alias)
            except IOError:
                pass

    def test_load_with_passwd(self):
        km = KeyManager(self.__context)
        key_pair = self.__context.crypto.generate_keys()
        vk = VirgilKey(self.__context, key_pair.private_key)
        alias = "key_manager_test_load_with_passwd"
        try:
            vk.save(alias, "SomeCoolPass")
            self.assertEqual(vk._VirgilKey__private_key, km.load(alias, "SomeCoolPass")._VirgilKey__private_key)
        finally:
            try:
                ks = DefaultKeyStorage()
                ks.delete(alias)
            except IOError:
                pass

    def test_import_key(self):
        km = KeyManager(self.__context)
        key_pair = self.__context.crypto.generate_keys()
        imported_key = km.import_key(VirgilBuffer(key_pair.private_key.value))
        self.assertEqual(imported_key._VirgilKey__private_key, key_pair.private_key)

    def test_import_key_with_passwd(self):
        key_pair = self.__context.crypto.generate_keys()
        km = KeyManager(self.__context)
        exported_key = self.__context.crypto.export_private_key(key_pair.private_key, "SomeCoolPass")
        self.assertEqual(
            km.import_key(VirgilBuffer(exported_key),"SomeCoolPass")._VirgilKey__private_key,
            key_pair.private_key
        )

    @property
    def __context(self):
        if not self._context:
            creds = Credentials(
                config.VIRGIL_APP_ID,
                open(config.VIRGIL_APP_KEY_PATH, "rb").read(),
                config.VIRGIL_APP_KEY_PASSWORD
            )
            self._context = VirgilContext(
                config.VIRGIL_ACCESS_TOKEN,
                creds
            )
        return self._context
