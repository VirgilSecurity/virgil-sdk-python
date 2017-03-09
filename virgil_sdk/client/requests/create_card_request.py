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
from virgil_sdk.client.requests import SignableRequest
from virgil_sdk.client import Utils
from virgil_sdk.client import Card


class CreateCardRequest(SignableRequest):
    """Create card signable API request."""

    def __init__(
            self,
            identity, # type: str
            identity_type, # type: str
            public_key, # type: Tuple[*int]
            data=None, # type: Optional[Dict[str, object]]
            info=None, # type: Optional[Dict[str, object]]
        ):
        # type: (...) -> None
        """Constructs new CreateCardRequest object"""
        super(CreateCardRequest, self).__init__()
        self.identity = identity
        self.identity_type = identity_type
        self.public_key = public_key
        self.data = data
        self.info = info

    def restore_from_snapshot_model(self, snapshot_model):
        # type: (Dict[str, obj]) -> None
        """Restores request from snapshot model.

        Args:
            snapshot_model: snapshot model dict
        """
        self.identity = snapshot_model['identity']
        self.identity_type = snapshot_model['identity_type']
        self.public_key = snapshot_model['public_key']
        self.data = snapshot_model.get('data', {})
        self.info = snapshot_model.get('info', {})

    def snapshot_model(self):
        # type: () -> Dict[str, obj]
        """Constructs snapshot model for exporting and signing.

        Returns:
            Dict containing snapshot data model used for card creation request.
        """
        return {
            'identity': self.identity,
            'identity_type': self.identity_type,
            'public_key': Utils.b64encode(self.public_key),
            'scope': Card.Scope.APPLICATION,
            'data': self.data,
            'info': self.info
        }
