# Copyright (C) 2016-2018 Virgil Security Inc.
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
from base64 import b64decode

from virgil_sdk.cards.card_signature import CardSignature
from virgil_sdk.cards.raw_card_content import RawCardContent


class Card(RawCardContent):
    """
    The Card class is the main entity of Virgil Services. Every user/device is
    represented with a Virgil Card which contains a public key and information about identity.
    """

    def __init__(
        self,
        card_id,  # type: str
        identity,  # type: str
        public_key,  # type: PublicKey
        version,  # type: str
        created_at,  # type: datetime
        signatures,  # type: list[CardSignature]
        previous_card_id,  # type: str
        content_snapshot,  # type: bytearray
        is_outdated=False  # type: bool
    ):
        # type: (...) -> None
        super(Card).__init__(identity, public_key, version, created_at, previous_card_id)
        self._id = card_id
        self.__signatures = signatures
        self._previous_card = None
        self._content_snapshot = content_snapshot
        self.is_outdated = is_outdated

    @classmethod
    def from_signed_model(cls, card_crypto, raw_singed_model, is_oudated=False):
        card = cls.from_snapshot(raw_singed_model.content_snapshot)

        card._public_key = card_crypto.import_public_key(bytearray(b64decode(card._public_key)))
        signatures = list()
        if raw_singed_model.signatures:
            for sign in raw_singed_model.signatures:
                card_signature = CardSignature(sign.signer, sign.signature, sign.snapshot, sign.extra_fields)
                signatures.append(card_signature)
        card._signatures = signatures
        card._is_outdated = is_oudated
        return card

    @property
    def id(self):
        """
        Gets the Card ID that uniquely identifies the Card in Virgil Services.
        Returns:
            Card id.
        """
        return self._id

    @property
    def previous_card(self):
        return self._previous_card

    @property
    def signatures(self):
        """
        Gets a list of signatures.
        Returns:
            List of signatures
        """
        return self.__signatures
