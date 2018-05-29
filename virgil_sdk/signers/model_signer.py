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

from virgil_sdk.client.raw_signature import RawSignature


class ModelSigner(object):

    SELF_SIGNER = "self"
    VIRGIL_SIGNER = "virgil"

    def __init__(
        self,
        card_crypto
    ):
        self.__card_crypto = card_crypto

    def sign(self, model, signer, signer_private_key, signature_snapshot=None, extra_fields=None):
        # type: (RawSignedModel, str, PrivateKey, bytearray, dict) -> None

        if model.signatures:
            if any(list(filter(lambda x: x.signer == signer, model.signatures))):
                raise ValueError("The model already has this signature")

        if extra_fields and not signature_snapshot:
            signature_snapshot = bytearray(json.dumps(str(extra_fields)))

        if signature_snapshot:
            extended_snapshot = bytearray(model.content_snapshot) + bytearray(signature_snapshot)
        else:
            extended_snapshot = model.content_snapshot

        signature_bytes = self.__card_crypto.generate_signature(extended_snapshot, signer_private_key)

        signature = RawSignature(signer, signature_bytes, signature_snapshot)
        model.signatures.add_signature(signature)

    def self_sign(self, model, signer_private_key, signature_snapshot=None, extra_fields=None):
        # type: (RawSignedModel, PrivateKey, bytearray, dict) -> None
        if extra_fields and not signature_snapshot:
            signature_snapshot = bytearray(json.dumps(str(extra_fields)))
        self.sign(model, self.SELF_SIGNER, signer_private_key, signature_snapshot)
