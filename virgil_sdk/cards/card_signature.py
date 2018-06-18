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
from base64 import b64encode


class CardSignature(object):
    """
    CardSignature provides signature for Card.
    """

    def __init__(
        self,
        signer,  # type: str
        signature,  # type: bytearray
        snapshot=None,  # type: bytearray
        extra_fields=None  # type: dict
    ):
        self._signer = signer
        self._signature = signature
        self._snapshot = snapshot
        self._extra_fields = extra_fields

    def to_json(self):
        res = {
            "signer": self.signer,
            "signature": b64encode(bytearray(self.signature)).decode(),

        }
        if self.snapshot:
            res["snapshot"] = b64encode(bytearray(self.snapshot)).decode()

        if self._extra_fields:
            res["extra_fields"] = b64encode(bytearray(self.extra_fields)).decode()
        return res

    @property
    def signer(self):
        return self._signer

    @property
    def signature(self):
        return self._signature

    @property
    def snapshot(self):
        return self._snapshot

    @property
    def extra_fields(self):
        return self._extra_fields
