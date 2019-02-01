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
from virgil_sdk.cards.raw_card_content import RawCardContent
from .raw_signature import RawSignature
from virgil_sdk.utils import Utils


class RawSignedModel(object):
    """
    The RawSignedModel provides transitional model of <see cref="Card"/>
    and used by CardClient.
    """

    def __init__(
        self,
        content_snapshot,  # type: Union[bytes, bytearray]
        signatures=None  # List[RawSignature]
    ):
        self._content_snapshot = content_snapshot
        self._signatures = signatures or []

    def to_json(self):
        """
        RawSignedModel json representation.
        """
        return Utils.json_dumps(
            {
                "content_snapshot": self.content_snapshot,
                "signatures": list(map(lambda x: x.to_json(), self.signatures))
            },
            separators=(',', ':'),
            sort_keys=True
        )

    def to_string(self):
        """
        Serialize to base64 encoded string.

        Returns:
            Base64 encoded string.
        """
        return Utils.b64encode(self.to_json().encode())

    def add_signature(self, signature):
        # type: (RawSignature) -> None
        """
        Add signature to RawSignedModel list.

        Args:
            signature: Card signature.

        Raises:
            ValueError: Attempt to add existing signature.
        """
        if signature.signer in list(map(lambda x: x.signer, self._signatures)):
            raise ValueError("Attempt to add an existing signature")
        else:
            self._signatures.append(signature)

    @property
    def content_snapshot(self):
        """
        Snapshot of RawCardContent.
        """
        return self._content_snapshot

    @property
    def signatures(self):
        """
        A list of signatures.
        """
        return self._signatures

    @classmethod
    def generate(cls, public_key, identity, created_at, previous_card_id=None):
        # type: (PublicKey, str, int, Optional[str]) -> RawSignedModel
        """
        Generate card RawSignedModel.

        Args:
            public_key: Card public key.
            identity: Unique card identity.
            created_at: Creation timestamp.
            previous_card_id: Previous card ID.

        Returns:
            Generate RawSignedModel instance.
        """
        raw_card = RawCardContent(
            identity=identity,
            public_key=public_key,
            created_at=created_at,
            previous_card_id=previous_card_id
        )
        return RawSignedModel(raw_card.content_snapshot)

    @classmethod
    def from_string(cls, raw_signed_model_string):
        # type: (str) -> RawSignedModel
        """Deserialize RawSignedModel from base64 encoded string."""
        return cls.from_json(Utils.b64_decode(raw_signed_model_string).decode())

    @classmethod
    def from_json(cls, raw_signed_model_json):
        # type: (Union[str, bytes, bytearray]) -> RawSignedModel
        """Deserialize RawSignedModel from json representation."""
        loaded_json = Utils.json_loads(raw_signed_model_json)
        content_snapshot = loaded_json["content_snapshot"]
        signatures = []
        for sign in loaded_json["signatures"]:
            if "signature_snapshot" in sign.keys():
                signature = RawSignature(
                    sign["signer"],
                    Utils.b64decode(sign["signature"]),
                    Utils.b64decode(sign["signature_snapshot"])
                )
                signatures.append(signature)
            else:
                signature = RawSignature(
                    sign["signer"],
                    Utils.b64decode(sign["signature"])
                )
                signatures.append(signature)
        return RawSignedModel(content_snapshot, signatures)
