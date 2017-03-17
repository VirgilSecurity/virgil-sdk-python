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
from virgil_sdk.api import VirgilBuffer


class VirgilKey(object):
    """The VirgilKey class represents a user's high-level Private key which provides
    a list of methods that allows to store the key and perform cryptographic operations like
    Decrypt, Sign etc."""

    def __init__(
            self,
            virgil_context,  # type: VirgilContext
            private_key  # type: PrivateKey
    ):
        # type: (...) -> None
        self.__context = virgil_context
        self.__private_key = private_key

    def export(self, password=None):
        # type: (Optional[str]) -> VirgilBuffer
        """Exports the VirgilKey to default format, specified in Crypto API.

        Args:
            password: password for private
        Returns:
            VirgilBuffer containing private key data
        """
        return VirgilBuffer(self.__context.crypto.export_private_key(self.__private_key, password))

    def sign(self, data):
        # type: (Union[VirgilBuffer, str, bytearray, bytes]) -> VirgilBuffer
        """ Generates a digital signature for specified data using current <see cref="VirgilKey"/>.
        Args:
            data: The data for which the digital signature will be generated.
        Returns:
            A new buffer that containing the result from performing the operation.
        Raises:
            ValueError if data argument not set or empty
        """
        if not data:
            raise ValueError("No data for sign")

        if isinstance(data, str):
            buffer = VirgilBuffer.from_string(data)
        elif isinstance(data, bytearray):
            buffer = VirgilBuffer(data)
        elif isinstance(data, bytes):
            buffer = VirgilBuffer(data)
        elif isinstance(data, VirgilBuffer):
            buffer = data
        else:
            raise TypeError("Unsupported type of data")

        return VirgilBuffer(self.__context.crypto.sign(buffer.get_bytearray(), self.__private_key))

    def decrypt(self, encrypted_data):
        # type: (Union[VirgilBuffer, str, bytearray, bytes]) -> VirgilBuffer
        """Decrypts the specified cipher data using VirgilKey
        Args:
            encrypted_data: The encrypted data.
        Returns:
            A byte array containing the result from performing the operation.
        Raises:
            ValueError if encrypted_data argument not set or empty
        """
        if not encrypted_data:
            raise ValueError("No data for decrypt")

        if isinstance(encrypted_data, str):
            buffer = VirgilBuffer.from_string(encrypted_data, "base64")
        elif isinstance(encrypted_data, bytearray):
            buffer = VirgilBuffer(encrypted_data)
        elif isinstance(encrypted_data, bytes):
            buffer = VirgilBuffer(encrypted_data)
        elif isinstance(encrypted_data, VirgilBuffer):
            buffer = encrypted_data
        else:
            raise TypeError("Unsupported type of data")

        return VirgilBuffer(self.__context.crypto.decrypt(buffer.get_bytearray(), self.__private_key))

    def save(self, key_name, password=None):
        # type: (str, Optional[str]) -> VirgilKey
        """Saves a current VirgilKey in secure storage.
        Args:
            key_name: The name of the key.
            password: The password (optional).
        Returns:
            Instance itself
        """
        exported_private_key = VirgilBuffer(self.__context.crypto.export_private_key(self.__private_key, password))
        self.__context.key_storage.store(key_name, exported_private_key.get_bytearray())
        return self

    def sign_then_encrypt(self, data_to_encrypt, recipients):
        # type: (Union[VirgilBuffer, str, bytearray, bytes], List[VirgilCard]) -> VirgilBuffer
        """Encrypts and signs the data.
        Args:
            data_to_encrypt: The data to be encrypted.
            recipients: The list of VirgilCard recipients.
        Returns:
            The encrypted data
        Raises:
            ValueError if recipient argument not set or empty
        """
        if not recipients:
            raise ValueError("No recipient specified")

        if isinstance(data_to_encrypt, str):
            buffer = VirgilBuffer.from_string(data_to_encrypt)
        elif isinstance(data_to_encrypt, bytearray):
            buffer = VirgilBuffer(data_to_encrypt)
        elif isinstance(data_to_encrypt, bytes):
            buffer = VirgilBuffer(data_to_encrypt)
        elif isinstance(data_to_encrypt, VirgilBuffer):
            buffer = data_to_encrypt
        else:
            raise TypeError("Unsupported type of data")

        public_keys = list(map(lambda x: x.public_key, recipients))

        cipher_data = self.__context.crypto.sign_then_encrypt(
            buffer.get_bytearray(),
            self.__private_key,
            *public_keys
        )
        return VirgilBuffer(cipher_data)

    def decrypt_then_verify(self, cipher_data, card):
        # type: (Union[VirgilBuffer, str, bytearray, bytes], VirgilCard) -> VirgilBuffer
        """Decrypts and verifies the data.
        Args:
            cipher_buffer: The data to be decrypted.
            card: The signer's VirgilCard.
        Returns:
            The decrypted data, which is the original plain text before encryption.
        Raises:
            ValueError is cipher buffer not set or empty
        """
        if not cipher_data:
            raise ValueError("No cipher buffer specified")

        if isinstance(cipher_data, str):
            buffer = VirgilBuffer.from_string(cipher_data, "base64")
        elif isinstance(cipher_data, bytearray):
            buffer = VirgilBuffer(cipher_data)
        elif isinstance(cipher_data, bytes):
            buffer = VirgilBuffer(cipher_data)
        elif isinstance(cipher_data, VirgilBuffer):
            buffer = cipher_data
        else:
            raise TypeError("Unsupported type of data")

        plain_text = self.__context.crypto.decrypt_then_verify(
            buffer.get_bytearray(),
            self.__private_key,
            card.public_key
        )
        return VirgilBuffer(plain_text)

    def export_public_key(self):
        # type: () -> VirgilBuffer
        """Exports the Public key value from current VirgilKey
        Returns:
            A new VirgilBuffer that contains Public Key value.
        """
        public_key = self.__context.crypto.extract_public_key(self.__private_key)
        return VirgilBuffer(public_key.value)
