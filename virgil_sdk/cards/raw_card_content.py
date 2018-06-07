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
import datetime
import json
from base64 import b64decode, b64encode


class RawCardContent(object):

    def __init__(
        self,
        identity,
        public_key,
        version,
        created_at,
        previous_card_id=None
    ):
        self._identity = identity
        self._public_key = public_key
        self._version = version
        self._created_at = created_at
        self._previous_card_id = previous_card_id
        self._content_snapshot = None

    @classmethod
    def from_snapshot(cls, content_snapshot):
        card_content = cls.__new__(cls)
        loaded_snapshot = json.loads(b64decode(content_snapshot).decode())
        card_content._identity = loaded_snapshot["identity"]
        card_content._public_key = loaded_snapshot["public_key"]
        card_content._version = loaded_snapshot["version"]
        card_content._created_at = loaded_snapshot["created_at"]
        if "previous_card_id" in loaded_snapshot.keys():
            card_content._previous_card_id = loaded_snapshot["previous_card_id"]
        else:
            card_content._previous_card_id = None
        card_content._content_snapshot = None
        return card_content

    @classmethod
    def from_signed_model(cls, card_crypto, raw_singed_model, is_oudated=False):
        card = cls.from_snapshot(raw_singed_model.content_snapshot)
        card._public_key = card_crypto.import_public_key(bytearray(b64decode(card._public_key)))
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
        if not self._content_snapshot:
            content = {
                "identity": self._identity,
                "public_key": b64encode(bytearray(self._public_key.raw_key)).decode(),
                "version": self._version,
                "created_at": self._created_at,
            }
            if self._previous_card_id:
                content.update({"previous_card_id": self._previous_card_id})
            self._content_snapshot = b64encode(
                json.dumps(content, sort_keys=True, separators=(',', ':')
                           ).encode()).decode()
        return self._content_snapshot
