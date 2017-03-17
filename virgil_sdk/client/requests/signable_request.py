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
import json
from virgil_sdk.cryptography.crypto import VirgilCrypto
from virgil_sdk.client.utils import Utils


class SignableRequest(object):
    """Base class for all API requests."""

    def __init__(self):
        # type: () -> None
        """Constructs new SignableRequest object"""
        self._snapshot = None
        self._signatures = {}

    def snapshot_model(self):
        # type: () -> Dict[str, obj]
        """Constructs snapshot model for exporting and signing.

        Should be implemented in the derived classes.

        Raises:
            NotImplementedError
        """
        raise NotImplementedError()

    def restore_from_snapshot_model(self, snapshot):
        # type: (Dict[str, obj]) -> None
        """Restores request from snapshot model.

        Should be implemented in the derived classes.

        Args:
            snapshot: snapshot model dict

        Raises:
            NotImplementedError
        """
        raise NotImplementedError()

    def restore(self, snapshot, signatures):
        # type: (str, Dict[str, str]) -> None
        """Restores request from snapshot.

        Args:
            snapshot: Json-encoded snapshot request will be restored from.
            signatures: Request signatures.
        """
        self._snapshot = snapshot
        self._signatures = signatures

        model = json.loads(bytearray(snapshot).decode())
        self.restore_from_snapshot_model(model)

    def take_snapshot(self):
        # type: () -> Tuple[*int]
        """Takes request data snapshot.

        Returns:
            Request snapshot bytes.
        """
        json_string = json.dumps(self.snapshot_model())
        snapshot = VirgilCrypto.strtobytes(json_string)
        return snapshot

    def export(self):
        # type: () -> str
        """Exports request snapshot.

        Returns:
            base64-encoded json representation of the request model.
        """
        request_model = self.request_model
        json_string = json.dumps(request_model)
        return Utils.b64encode(json_string)

    def sign_with(self, fingerprint_id, signature):
        # type: (str, str) -> None
        """Adds signature to request."""
        self.signatures[fingerprint_id] = Utils.b64encode(signature)

    @property
    def request_model(self):
        # type: () -> Dict[str, object]
        """Request model used for json representation."""
        return {
            'content_snapshot': Utils.b64encode(self.snapshot),
            'meta': {
                'signs': self.signatures
            }
        }

    @property
    def snapshot(self):
        # type: () -> Tuple[*int]
        """Request data snapshot"""
        if not self._snapshot:
            self._snapshot = self.take_snapshot()
        return self._snapshot

    @snapshot.setter
    def snapshot(self, snapshot):
        # type: (Tuple[*int]) -> None
        self._snapshot = snapshot

    @property
    def signatures(self):
        # type: () -> Dict[str, str]
        """Request signatures"""
        return self._signatures

    @signatures.setter
    def signatures(self, signatures):
        # type: (Dict[str, str]) -> None
        self._signatures = signatures
