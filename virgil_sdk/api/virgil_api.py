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
from virgil_sdk.api import IdentitiesManager
from virgil_sdk.api import VirgilBuffer
from virgil_sdk.api import VirgilContext
from virgil_sdk.api.card_manager import CardManager
from virgil_sdk.api.key_manager import KeyManager


class Virgil(object):
    """The Virgil class is a high-level API that provides easy access to
    Virgil Security services and allows to perform cryptographic operations by using two domain entities
    VirgilKey and VirgilCard. Where the VirgilKey is an entity
    that represents a user's Private key, and the VirgilCard is the entity that represents
    user's identity and a Public key."""

    def __init__(
            self,
            access_token=None,  # type: str
            context=None  # type: VirgilContext
    ):
        # type: (...) -> None
        self.__access_token = access_token
        self._context = context
        self.keys = KeyManager(self.__context)
        self.cards = CardManager(self.__context)
        self.identities = IdentitiesManager(self.__context)

    def encrypt_for(self, cards, data):
        # type: (List[VirgilCard], Union[VirgilBuffer, str, bytearray, bytes]) -> VirgilBuffer
        """Encrypt to multiply cards"""

        if cards:
            public_keys = list(map(lambda x: x.public_key, cards))
        else:
            raise ValueError("Card list for encryption empty")

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

        cipher_data = self.__context.crypto.encrypt(buffer.get_bytearray(), *public_keys)
        return VirgilBuffer(cipher_data)


    @property
    def __context(self):
        # type: () -> VirgilContext
        """Gets context for further use in api"""
        if not self._context:
            self._context = VirgilContext(self.__access_token)
        return self._context
