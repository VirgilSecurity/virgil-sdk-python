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
import json


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
                "Identity": self.identity,
                "PublicKey": self.public_key,
                "Version": self.version,
                "PreviousCardId": self.previous_card_id
            }
            self._content_snapshot = json.dumps(content).encode()
        return self.content_snapshot
