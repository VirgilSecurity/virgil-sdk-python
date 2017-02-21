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
from virgil_sdk.client.requests.signable_request import SignableRequest


class RevokeCardRequest(SignableRequest):
    """Revoke card signable API request."""

    class Reasons(object):
        """Enum containing possible revocation reasons."""
        Unspecified = 'unspecified'
        Compromised = 'compromised'

    def __init__(
            self,
            card_id, # type: str
            reason=Reasons.Unspecified, # type: str
        ):
        # type: (...) -> None
        """Constructs new RevokeCardRequest object"""
        super(RevokeCardRequest, self).__init__()
        self.card_id = card_id
        self.reason = reason

    def restore_from_snapshot_model(self, snapshot_model):
        # type: (Dict[str, obj]) -> None
        """Restores request from snapshot model.

        Args:
            snapshot_model: snapshot model dict
        """
        self.card_id = snapshot_model['card_id']
        self.reason = snapshot_model['revocation_reason']

    def snapshot_model(self):
        # type: () -> Dict[str, obj]
        """Constructs snapshot model for exporting and signing.

        Returns:
            Dict containing snapshot data model used for card revocation request.
        """
        return {
            'card_id': self.card_id,
            'revocation_reason': self.reason,
        }
