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
from collections import OrderedDict

from virgil_sdk.utils import Utils


class RawCardContent(object):
    """
    RawCardContent provides content of Virgil Card.
    """

    def __init__(
        self,
        identity,  # type: str
        public_key,  # type: PublicKey
        created_at,  # type datetime
        version="5.0",  # type: str
        previous_card_id=None,  # type: str
    ):
        self._identity = identity
        self._public_key = public_key
        self._version = version
        self._created_at = created_at
        self._previous_card_id = previous_card_id
        self._content_snapshot = None

    def to_json(self):
        """
        Raw card content json representation.

        Returns:
            Serialize raw card content to json.
        """
        return OrderedDict({
            "identity": self.identity,
            "public_key": self.public_key,
            "version": self.version,
            "created_at": self.created_at,
            "previous_card_id": self.previous_card_id,
            "content_snapshot": self.content_snapshot
        })

    @classmethod
    def from_snapshot(cls, content_snapshot):
        # type: (dict) -> RawCardContent
        """
        RawCardContent deserializer from snapshot representation.

        Args:
            content_snapshot: RawCardContent serialized snapshot.

        Returns:
            Loaded RawCardContent instance.
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
    def from_signed_model(cls, card_crypto, raw_singed_model):
        # type: (Any, RawSignedModel) -> RawCardContent
        """
        RawCardContent deserializer from RawSignedModel representation.

        Args:
            card_crypto: CardCrypto witch provides crypto operations.
            raw_singed_model: Card raw signed model.

        Returns:
            Loaded RawCardContent instance.
        """
        card = cls.from_snapshot(raw_singed_model.content_snapshot)
        card._public_key = card_crypto.import_public_key(bytearray(Utils.b64_decode(card._public_key)))
        return card

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
    def content_snapshot(self):
        """
        RawCardContent snapshot.

        Returns:
            Snapshot of RawCardContent.
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
