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


class PrivateKeyExporter(object):
    """
    PrivateKeyExporter provides a list of methods that lets user to export and import private key.
    Args:
        password: The password for private key.
    """

    def __init__(
        self,
        crypto,
        password=None  # type: str
    ):
        self.crypto = crypto
        self.__password = password

    def export_private_key(self, private_key):
        # type: (PrivateKey) -> Union[bytes, bytearray]
        """
        Exports the PrivateKey into material representation. If PrivateKeyExporter was
        instantiated with password then it will be used to export private key.
        Args:
            private_key: The private key.
        Returns:
            Private key in material representation of bytes.
        """
        if self.__password:
            return self.crypto.export_private_key(private_key, self.__password)
        else:
            return self.crypto.export_private_key(private_key)

    def import_private_key(self, key_data):
        # type: (Union[bytes, bytearray]) -> PrivateKey
        """
        Imports the private key from its material representation. If PrivateKeyExporter was
        instantiated with password then it will be used to import private key.
        Args:
            key_data: The private key material representation bytes.
        Returns:
            The instance of PrivateKey imported.
        """
        if self.__password:
            return self.crypto.import_private_key(key_data, self.__password)
        else:
            return self.crypto.import_private_key(key_data)
