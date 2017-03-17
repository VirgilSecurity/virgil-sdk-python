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

from virgil_sdk.client import CardValidator
from virgil_sdk.client import VirgilClient
from virgil_sdk.cryptography import VirgilCrypto
from virgil_sdk.storage import DefaultKeyStorage


class VirgilContext(object):
    """
    The class manages the Virgil api dependencies during run time.
    It also contains a list of properties that uses to configurate the high-level components.
    """

    def __init__(
            self,
            access_token=None,  # type: Optional[str]
            credentials=None,  # type: Optional[Creantials]
            card_verifiers=None,  # type: Optional[List[CardVerifierInfo]]
            crypto=None,  # type: Optional[Crypto]
            key_storage=None,  # type: Optional[KeyStorage]
            client_params=None  # type: Optional[dict]
    ):
        # type: (...) -> None
        """Initializes a new instance of the VirgilContext class."""
        self.access_token = access_token
        self.credentials = credentials
        self.client_params = client_params
        self._card_verifiers = card_verifiers
        self._crypto = crypto
        self._key_storage = key_storage
        self._client = None

    @property
    def crypto(self):
        """Gets a cryptographic keys storage."""
        if not self._crypto:
            self._crypto = VirgilCrypto()
        return self._crypto

    @property
    def key_storage(self):
        """Sets a cryptographic keys storage."""
        if not self._key_storage:
            self._key_storage = DefaultKeyStorage()
        return self._key_storage

    @property
    def client(self):
        """Gets a Virgil Security services client."""
        if not self._client:
            validator = CardValidator(self.crypto)
            if self._card_verifiers:
                for verifier in self._card_verifiers:
                    public_key = self.crypto.import_public_key(verifier.public_key.get_bytearray())
                    validator.add_verifier(verifier.card_id, public_key)
            if self.client_params:
                self._client = VirgilClient(*self.client_params)
                self._client.card_validator = validator
            else:
                self._client = VirgilClient(access_token=self.access_token)
                self._client.card_validator = validator
        return self._client
