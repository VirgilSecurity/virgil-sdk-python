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
import binascii

from virgil_sdk.cards.card_signature import CardSignature
from virgil_sdk.client import RawSignature
from virgil_sdk.utils import Utils


class Card(object):
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
        super(Card, self).__init__(identity, public_key, version, created_at, previous_card_id)
        self._id = card_id
        self._identity = identity
        self._version = version
        self._created_at = created_at
        self._previous_card_id = previous_card_id
        self._public_key = public_key
        self.__signatures = signatures
        self.previous_card = None
        self._content_snapshot = content_snapshot
        self.is_outdated = is_outdated

    @classmethod
    def __generate_card_id(cls, card_crypto, content_snapshot):
        # type: (Any, dict) -> str
        """
        Generate card id from content snapshot
        Args:
            card_crypto: Users CardCrypto witch provides cryptographic operations.
            content_snapshot: Card content snapshot
        Returns:
            Generated Card id.
        """
        fingerprint = card_crypto.generate_sha512(bytearray(content_snapshot))
        card_id = binascii.hexlify(bytearray(fingerprint)[:32]).decode()
        return card_id

    @classmethod
    def from_snapshot(cls, content_snapshot):
        # type: (str) -> Card
        """
        Creates card from content snapshot.
        Args:
            content_snapshot: Model content snapshot.

        Returns:
            Card created from model content snapshot.
        """
        card_content = cls.__new__(cls)
        loaded_snapshot = Utils.json_loads(Utils.b64_decode(content_snapshot))
        card_content._identity = loaded_snapshot["identity"]
        card_content._public_key = loaded_snapshot["public_key"]
        card_content._version = loaded_snapshot["version"]
        card_content._created_at = loaded_snapshot["created_at"]
        if "previous_card_id" in loaded_snapshot.keys():
            card_content._previous_card_id = loaded_snapshot["previous_card_id"]
        else:
            card_content._previous_card_id = None
        card_content._content_snapshot = content_snapshot
        return card_content

    @classmethod
    def from_signed_model(cls, card_crypto, raw_singed_model, is_outdated=False):
        # type: (Any, RawSignedModel, bool) -> Card
        """
        Creates card from SignedModel snapshot and signatures.
        Args:
            card_crypto: Users CardCrypto witch provides cryptographic operations.
            raw_singed_model: Card RawSignedModel
            is_outdated: State of obsolescence

        Returns:
            Card created from RawSignedModel.
        """
        card = cls.from_snapshot(raw_singed_model.content_snapshot)
        card.previous_card = None
        card.is_outdated = is_outdated

        card._id = cls.__generate_card_id(card_crypto, Utils.b64_decode(raw_singed_model.content_snapshot))
        card._public_key = card_crypto.import_public_key(bytearray(Utils.b64_decode(card._public_key)))
        signatures = list()
        if raw_singed_model.signatures:
            for sign in raw_singed_model.signatures:
                if isinstance(sign, dict):
                    if "snapshot" in sign.keys():
                        card_signature = CardSignature(
                            sign["signer"],
                            bytearray(Utils.b64decode(sign["signature"])),
                            sign["snapshot"]
                        )
                    else:
                        card_signature = CardSignature(sign["signer"], bytearray(Utils.b64decode(sign["signature"])))
                    signatures.append(card_signature)
                if isinstance(sign, CardSignature):
                    card_signature = sign
                    signatures.append(card_signature)
                if isinstance(sign, RawSignature):
                    card_signature = CardSignature(sign.signer, sign.signature, sign.snapshot)
                    signatures.append(card_signature)
        card.__signatures = signatures
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
    def identity(self):
        """
        Gets the identity value that can be anything which identifies the user in your application.
        Returns:
            User identity.
        """
        return self._identity

    @property
    def public_key(self):
        """
        Gets the public key.
        Returns:
            Public key.
        """
        return self._public_key

    @property
    def version(self):
        """
        Gets the version of the card.
        Returns:
            Card version.
        """
        return self._version

    @property
    def created_at(self):
        """
        Gets the date and time fo card creation in UTC.
        Returns:
            Creation date in UTC datetime.
        """
        return self._created_at

    @property
    def previous_card_id(self):
        """
        Get previous Card ID that current card is used to override to.
        Returns:
            Previous card id.
        """
        return self._previous_card_id

    @property
    def signatures(self):
        """
        Gets a list of signatures.
        Returns:
            List of signatures
        """
        return self.__signatures

    @property
    def content_snapshot(self):
        """
        Card content snapshot
        Returns:
            Card snapshot.
        """
        if not self._content_snapshot:
            content = {
                "identity": self._identity,
                "public_key": Utils.b64encode(self._public_key.raw_key),
                "version": self._version,
                "created_at": self._created_at,
            }
            if self._previous_card_id:
                content.update({"previous_card_id": self._previous_card_id})
            self._content_snapshot = Utils.b64encode(
                Utils.json_dumps(content, sort_keys=True, separators=(',', ':')).encode()
            )
        return self._content_snapshot

