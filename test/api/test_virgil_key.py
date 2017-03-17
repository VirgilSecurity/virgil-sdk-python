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

from virgil_sdk.api import VirgilBuffer
from virgil_sdk.api import VirgilContext
from virgil_sdk.api import VirgilKey
from virgil_sdk.cryptography import VirgilCrypto
from virgil_sdk.storage import DefaultKeyStorage


class VirgilKeyTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(VirgilKeyTest, self).__init__(*args, **kwargs)
        self.__crypto = VirgilCrypto()

    def test_export(self):
        private_key = self.__crypto.generate_keys().private_key
        context = VirgilContext()
        vk = VirgilKey(context, private_key)
        self.assertEqual(vk.export().get_bytearray(), bytearray(self.__crypto.export_private_key(private_key)))

    def test_sign(self):
        private_key = self.__crypto.generate_keys().private_key
        context = VirgilContext()
        vk = VirgilKey(context, private_key)
        data_string = "hello world"
        data = VirgilBuffer.from_string(data_string)
        self.assertEqual(vk.sign(data).get_bytearray(),
                         bytearray(self.__crypto.sign(bytearray(data_string, "utf-8"), private_key)))

    def test_decrypt(self):
        key_pair = self.__crypto.generate_keys()
        private_key = key_pair.private_key
        context = VirgilContext()
        vk = VirgilKey(context, private_key)
        data_string = "hello world"
        data = VirgilBuffer.from_string(data_string)
        encrypted_data = VirgilBuffer(self.__crypto.encrypt(data.get_bytearray(), key_pair.public_key))
        self.assertEqual(data.get_bytearray(), vk.decrypt(encrypted_data).get_bytearray())

    def test_save(self):
        private_key = self.__crypto.generate_keys().private_key
        context = VirgilContext()
        vk = VirgilKey(context, private_key)
        alias = "virgil_key_test_save"
        km = DefaultKeyStorage()
        try:
            vk.save(alias)
            self.assertEqual(bytearray(private_key.value), km.load(alias))
        finally:
            try:
                km.delete(alias)
            except IOError:
                pass

    def test_save_with_passwd(self):
        private_key = self.__crypto.generate_keys().private_key
        context = VirgilContext()
        vk = VirgilKey(context, private_key)
        alias = "virgil_key_test_save"
        km = DefaultKeyStorage()
        try:
            vk.save(alias, "SomeCoolPass")
            self.assertEqual(private_key.value, self.__crypto.import_private_key(bytearray(km.load(alias)), "SomeCoolPass").value)
        finally:
            try:
                km.delete(alias)
            except IOError:
                pass

    def test_sign_then_encrypt(self):
        alice_keys = self.__crypto.generate_keys()
        bob_keys = self.__crypto.generate_keys()
        test_keys = self.__crypto.generate_keys()
        context = VirgilContext()
        data_string = "hello world"
        data = VirgilBuffer.from_string(data_string)
        recipients = [alice_keys, bob_keys]
        vk = VirgilKey(context, test_keys.private_key)
        cipher_data = vk.sign_then_encrypt(data, recipients)
        self.assertEqual(
            data.get_bytearray(),
            bytearray(self.__crypto.decrypt_then_verify(
                cipher_data.get_bytearray(),
                alice_keys.private_key,
                test_keys.public_key
            ))
        )
        self.assertEqual(
            data.get_bytearray(),
            bytearray(self.__crypto.decrypt_then_verify(
                cipher_data.get_bytearray(),
                bob_keys.private_key,
                test_keys.public_key
            ))
        )

    def test_decrypt_then_verify(self):
        alice_keys = self.__crypto.generate_keys()
        test_keys = self.__crypto.generate_keys()
        data_string = "hello world"
        data = VirgilBuffer.from_string(data_string)
        context = VirgilContext()
        vk = VirgilKey(context, test_keys.private_key)
        cipher_data = self.__crypto.sign_then_encrypt(
            data.get_bytearray(),
            alice_keys.private_key,
            test_keys.public_key
        )
        self.assertEqual(
            data.get_bytearray(),
            vk.decrypt_then_verify(VirgilBuffer(cipher_data), alice_keys).get_bytearray()
        )

    def test_export_public_key(self):
        test_keys = self.__crypto.generate_keys()
        context = VirgilContext()
        vk = VirgilKey(context, test_keys.private_key)
        self.assertEqual(bytearray(test_keys.public_key.value), vk.export_public_key().get_bytearray())