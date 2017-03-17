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
from virgil_sdk.api import VirgilKey


class KeyManager(object):
    """ The KeysManager class provides a list of methods to generate the VirgilKey's
    and further them storage in secure place."""

    def __init__(self, context):
        self.context = context

    def generate(self):
        # type: () -> VirgilKey
        """Generates a new VirgilKey with default parameters.
        Returns:
            An instance of VirgilKey class.
        """
        key_pair = self.context.crypto.generate_keys()
        return VirgilKey(self.context, key_pair.private_key)

    def load(self, key_name, key_password=None):
        # type: (str, Optional[str]) -> VirgilKey
        """Loads the VirgilKey from current storage by specified key name.
        Args:
            key_name: The name of the Key.
            key_password: The Key password.
        Returns:
            An instance of VirgilKey class.
        Raises:
            ValueError when key name empty.
        """
        if not key_name:
            raise ValueError("Key name empty")
        raw_key = self.context.key_storage.load(key_name)
        private_key = self.context.crypto.import_private_key(bytearray(raw_key), key_password)
        return VirgilKey(self.context, private_key)

    def import_key(self, key_buffer, key_password=None):
        # type: (VirgilBuffer, str) -> VirgilKey
        """Imports the VirgilKey from buffer.
        Args:
            key_buffer: The buffer with Key.
            key_password: The Key password.
        Returns:
            An instance of VirgilKey class.
        """
        private_key = self.context.crypto.import_private_key(key_buffer.get_bytearray(), key_password)
        return VirgilKey(self.context, private_key)