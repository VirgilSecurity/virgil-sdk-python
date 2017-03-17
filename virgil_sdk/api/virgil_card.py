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
from virgil_sdk.client import Card
from virgil_sdk.client import RequestSigner
from virgil_sdk.client import Utils
from virgil_sdk.client.requests import CreateCardRequest
from virgil_sdk.client.requests import CreateGlobalCardRequest


class VirgilCard(object):
    """A Virgil Card is the main entity of the Virgil Security services, it includes an information
    about the user and his public key. The Virgil Card identifies the user by one of his available
    types, such as an email, a phone number, etc."""

    def __init__(
        self,
        context,  # type: Context
        card  # type: Card
    ):
        # type: (...) -> None
        self.__context = context
        self.__card = card
        self._public_key = None
        self._id = None
        self._identity = None
        self._identity_type = None
        self._custom_fields = None

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def encrypt(self, data):
        # type: (Union[VirgilBuffer, str, bytearray, bytes]) -> VirgilBuffer
        """Encrypts the specified data for current VirgilCard recipient.
        Args:
            buffer: The data to be encrypted.
        Returns:
            Encrypted data
        Raises:
            ValueError if VirgilBuffer empty
        """

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

        if not buffer:
            raise ValueError("VirgilBuffer empty")
        cipher_data = self.__context.crypto.encrypt(buffer.get_bytearray(), self.public_key)
        return VirgilBuffer(cipher_data)

    def verify(self, data, signature):
        # type: (Union[VirgilBuffer, str, bytearray, bytes], VirgilBuffer) -> bool
        """Verifies the specified buffer and signature with current VirgilCard recipient.
        Args:
            buffer: The data to be verified.
            signature: The signature used to verify the data integrity.
        Returns:
            Boolean verification result
        Raises:
            ValueError is buffer or signature empty
        """
        if not data:
            raise ValueError("Data empty")
        if not signature:
            raise ValueError("Signatures empty")

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

        is_valid = self.__context.crypto.verify(
            buffer.get_bytearray(),
            signature.get_bytearray(),
            self.public_key
        )
        return is_valid

    def export(self):
        # type: () -> str
        """Exports a current VirgilCard instance into base64 encoded string.
        Returns:
            A base64 string that represents a VirgilCard.
        """
        card_json = Utils.json_dumps(
            {
                "id": self.__card.id,
                "content_snapshot": VirgilBuffer(self.__card.snapshot).to_string("base64"),
                "meta": {
                    "card_version": self.__card.version,
                    "signs": self.__card.signatures
                }
            }
        )
        return VirgilBuffer.from_string(card_json).to_string("base64")

    def publish(self):
        # type: () -> None
        """Publishes a current VirgilCard to the Virgil Security services."""
        if self.__card.scope == Card.Scope.GLOBAL:
            self.__publish_global()
        else:
            create_card_request = CreateCardRequest(
                self.identity,
                self.identity_type,
                self.public_key,
                self.__card.data
            )
            create_card_request.signatures = self.__card.signatures
            create_card_request.snapshot = self.__card.snapshot
            request_signer = RequestSigner(self.__context.crypto)
            request_signer.authority_sign(
                create_card_request,
                self.__context.credentials.app_id,
                self.__context.credentials.get_app_key(self.__context.crypto)
            )
            self.__card = self.__context.client.create_card_from_request(create_card_request)

    def __publish_global(self):
        # type: (str) -> None
        """Publishes a current VirgilCard to the Virgil Security services into global scope.
        Raises:
            ValueError if identity token empty
        """

        create_global_card_request = CreateGlobalCardRequest(
            self.identity,
            self.identity_type,
            self.public_key,
            self.__card.validation_token,
            self.__card.data
        )
        create_global_card_request.signatures = self.__card.signatures
        create_global_card_request.snapshot = self.__card.snapshot
        self.__card = self.__context.client.create_global_card_from_request(create_global_card_request)

    @property
    def id(self):
        # type: () -> str
        """Gets the unique identifier for the Virgil Card."""
        return self.__card.id

    @property
    def identity(self):
        # type: () -> str
        """Gets the value of current Virgil Card identity."""
        return self.__card.identity

    @property
    def identity_type(self):
        # type: () -> str
        """Gets the identityType of current Virgil Card identity."""
        return self.__card.identity_type

    @property
    def custom_fields(self):
        # type: () -> dict
        """Gets the custom VirgilCard parameters."""
        return self.__card.data

    @property
    def public_key(self):
        # type: () -> PublicKey
        """Gets a Public key that is assigned to current VirgilCard."""
        return self.__context.crypto.import_public_key(self.__card.public_key)
