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
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISINGim
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
import hashlib
import os
import platform
from .key_storage import KeyStorage


class DefaultKeyStorage(KeyStorage):
    """The provides protected storage using the user
    credentials to encrypt or decrypt keys."""

    def __init__(self):
        # type: (...) -> None
        super(DefaultKeyStorage, self).__init__()
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

    def store(self, key_name, key_value):
        # type: (str, bytes) -> None
        """Stores the key to the given alias.
        Args:
            key_name: key name in storage
            key_value: key value for store
        Raises:
            EnvironmentError if cannot identify operationg system for build user home path.
        """
        key_file_path = os.path.join(self.__key_storage_path, self.__secure_key_file_name(key_name))
        if not os.path.exists(self.__key_storage_path):
            os.mkdir(self.__key_storage_path)
        if os.path.exists(key_file_path):
            raise ValueError("Can't store key {}, key with the same name already stored".format(key_name))
        open(key_file_path, "wb").write(key_value)

    def load(self, key_name):
        # type: (str) -> bytes
        """Loads the key associated with the given alias.
        Args:
            key_name: key name in storage
        Returns:
            The requested key
        Raises:
            IOError if cannot find key file in storage folder
        """
        key_file_path = os.path.join(self.__key_storage_path, self.__secure_key_file_name(key_name))
        if not os.path.exists(key_file_path):
            raise IOError("Can't load key {}, file not found in storage".format(key_name))
        return bytes(open(key_file_path, "rb").read())

    def delete(self, key_name):
        # type: (str) -> None
        """Checks if the given alias exists in this keystore.
        Args:
            key_name: key name in storage
        Raises:
            IOError if cannot find key file in storage folder
        """
        key_file_path = os.path.join(self.__key_storage_path, self.__secure_key_file_name(key_name))
        if not os.path.exists(key_file_path):
            raise IOError("Can't delete key {}, file not found in storage".format(key_name))
        os.remove(key_file_path)

    @staticmethod
    def __secure_key_file_name(key_name):
        return hashlib.sha384(key_name.encode("utf-8")).hexdigest()
