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
from virgil_sdk.storage.key_storage import KeyStorage
from virgil_sdk.storage.key_entry import KeyEntry


class PrivateKeyStorage(object):

    def __init__(self, key_exporter, key_storage=KeyStorage()):
        self.key_storage = key_storage
        self.__key_exporter = key_exporter

    def store(self, private_key, name, meta=None):
        # type: (Any, Union[bytes, bytearray], dict) -> None
        """
        Stores the key to the given alias.

        Args:
            private_key: PrivateKey representation.
            name: Key name in storage.
            meta: Additional data.
        """
        if not name:
            raise ValueError("No name provided for store.")
        if not private_key:
            raise ValueError("No key provided for store.")
        exported_key_data = self.__key_exporter.export_private_key(private_key)
        key_entry = KeyEntry(name, exported_key_data, meta)
        self.key_storage.store(key_entry)

    def load(self, name):
        # type: (str) -> Tuple(Any, dict)
        """
        The requested key and meta data, or None if the given alias does not exist or does
        not identify a key-related entry.

        Args:
            name: Key name in storage.

        Returns:
            Tuple of key and additional data loaded from storage.
        """
        if not name:
            ValueError("No alias provided for key load.")
        key_entry = self.key_storage.load(name)
        private_key = self.__key_exporter.import_private_key(key_entry["value"])
        return private_key, key_entry["meta"]

    def delete(self, name):
        # type: (str) -> None
        """
        Checks if the given alias exists in this storage and delete it.

        Args:
            name: Key alias in storage.
        """
        if not name:
            ValueError("No alias provided for key delete.")
        self.key_storage.delete(name)
