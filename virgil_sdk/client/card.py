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
from virgil_sdk.client.utils import Utils

class Card(object):
    """Model representing cards information."""
    class Scope(object):
        """Card scope enumeration."""
        APPLICATION = "application"
        GLOBAL = "global"

    def __init__(
            self,
            identity,  # type: str
            identity_type,  # type: str
            public_key,  # type: Tuple[*int]
            scope=None,  # type: Optional[Scope]
            id=None,  # type: Optional[str]
            snapshot=None,  # type: Optional[Tuple[*int]]
            data=None,      # type: Optional[dict]
            device=None,  # type: Optional[str]
            device_name=None,  # type: Optional[str]
            version=None,  # type: Optional[str]
            signatures=None,  # type: Optional[Dict[str]]
            validation_token=None # type: Optional[str]
        ):
        # type: (...) -> None
        self.id = id
        self.snapshot = snapshot
        self.identity = identity
        self.identity_type = identity_type
        self.public_key = public_key
        self.scope = scope
        self.data = data or {}
        self.device = device
        self.device_name = device_name
        self.version = version
        self.signatures = signatures or {}
        self.validation_token = validation_token

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        return False

    def __ne__(self, other):
        if isinstance(other, self.__class__):
            return not self.__eq__(other)
        return NotImplemented

    def __hash__(self):
        return hash(tuple(sorted(self.__dict__.items())))

    def __str__(self):
        return "Cards {} {} {} {} {}".format(
            self.id,
            self.identity,
            self.identity_type,
            self.scope,
            self.public_key,
        )

    def __repr__(self):
        return str(self)

    @classmethod
    def from_response(cls, response):
        # type: (Dict[str, str]) -> Card
        """Create new Card from response containing json-encoded snapshot.

        Args:
            response: Cards service response containing base64 encoded content_snapshot.

        Returns:
            Card model restored from snapshot.
        """
        snapshot = Utils.b64decode(response["content_snapshot"])
        snapshot_model = Utils.json_loads(snapshot)
        info = snapshot_model.get("info", {}) or {}

        return cls(
            id=response["id"],
            snapshot=snapshot,
            identity=snapshot_model["identity"],
            identity_type=snapshot_model["identity_type"],
            public_key=tuple(bytearray(Utils.b64decode(snapshot_model["public_key"]))),
            device=info.get("device"),
            device_name=info.get("device_name"),
            data=snapshot_model.get("data", {}),
            scope=snapshot_model["scope"],
            version=response["meta"]["card_version"],
            signatures=response["meta"]["signs"]
        )
