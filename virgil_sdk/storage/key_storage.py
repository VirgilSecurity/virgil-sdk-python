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
import hashlib
import os
import platform
from virgil_sdk.utils import Utils


class KeyStorage(object):
    """The provides protected storage using the user
    credentials to encrypt or decrypt keys."""

    def __init__(self):
        # type: (...) -> None
        self._key_storage_path = None

    @property
    def __key_storage_path(self):
        home = None
        if platform.system() == "Windows":
            home = os.getenv("HOMEPATH")
        if platform.system() == "Linux" or platform.system() == "Darwin":
            home = os.getenv("HOME")
        if not home:
            raise EnvironmentError("Can't identify operating system")
        return os.path.join(home, ".virgil")

    def store(self, key_entry):
        # type: (KeyEntry) -> None
        """Stores the key and data to the given alias.

        Args:
            key_entry: Given key entry for store.

        Raises:
            EnvironmentError: if cannot identify operation system for build user home path.
        """
        if not key_entry:
            raise ValueError("No key entry for store.")
        key_file_path = os.path.join(self.__key_storage_path, self.__secure_key_file_name(key_entry.name))
        if not os.path.exists(self.__key_storage_path):
            os.mkdir(self.__key_storage_path)
        if os.path.exists(key_file_path):
            raise ValueError("Can't store key {}, key with the same name already stored".format(key_entry.name))
        file = open(key_file_path, "wb")
        file.write(key_entry.to_json().encode())
        file.close()

    def load(self, name):
        # type: (str) -> dict
        """Loads the key associated with the given alias.

        Args:
            name: Key name in storage.

        Returns:
            The requested key.

        Raises:
            IOError: if cannot find key file in storage folder
        """
        if not name:
            raise ValueError("No alias provided for load key.")
        key_file_path = os.path.join(self.__key_storage_path, self.__secure_key_file_name(name))
        if not os.path.exists(key_file_path):
            raise ValueError("Can't load key {}, not found in storage".format(name))
        key_file = open(key_file_path, "rb")
        key_file_data = key_file.read()
        key_file.close()
        return Utils.json_loads(bytes(key_file_data).decode())

    def delete(self, name):
        # type: (str) -> None
        """Checks if the given alias exists in this keystore.

        Args:
            name: key name in storage

        Raises:
            IOError if cannot find key file in storage folder
        """
        if not name:
            raise ValueError("No alias provided for key deleting.")
        key_file_path = os.path.join(self.__key_storage_path, self.__secure_key_file_name(name))
        if not os.path.exists(key_file_path):
            raise ValueError("Can't delete key {}, file not found in storage".format(name))
        os.remove(key_file_path)

    @staticmethod
    def __secure_key_file_name(key_name):
        return hashlib.sha384(key_name.encode("utf-8")).hexdigest()
