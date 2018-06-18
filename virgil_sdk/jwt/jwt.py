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

from virgil_sdk.utils.b64utils import b64_decode, b64_encode
from .jwt_header_content import JwtHeaderContent
from .jwt_body_content import JwtBodyContent
from virgil_sdk.jwt.abstractions.access_token import AccessToken


class Jwt(AccessToken):

    def __init__(self, jwt_header_content=None, jwt_body_content=None, signature_data=None):
        self._header_content = jwt_header_content
        self._body_content = jwt_body_content
        self._signature_data = signature_data
        self._without_signature = b64_encode(json.dumps(self._header_content.json, sort_keys=True).encode())\
                                  + "." +\
                                  b64_encode(json.dumps(self._body_content.json, sort_keys=True).encode())
        self._unsigned_data = self._without_signature.encode()
        self._string_representation = self._without_signature
        if self._signature_data:
            self._string_representation += "." + b64_encode(bytes(self._signature_data))

    def __str__(self):
        return self._string_representation

    def __unicode__(self):
        return self._string_representation

    def __bytes__(self):
        return self._unsigned_data

    def __eq__(self, other):
        return all([
            self._body_content == other._body_content,
            self._header_content == other._header_content,
            self.unsigned_data == other.unsigned_data,
            self.signature_data == other.signature_data,
        ])

    @classmethod
    def from_string(cls, jwt_string):
        parts = jwt_string.split(".")
        if len(parts) is not 3:
            raise ValueError("Wrong JWT format.")

        try:
            jwt = cls.__new__(cls)
            jwt._header_content = JwtHeaderContent.from_json(json.loads(str(b64_decode(parts[0]).decode())))
            jwt._body_content = JwtBodyContent.from_json(json.loads(str(b64_decode(parts[1]).decode())))
            jwt._signature_data = b64_decode(parts[2])
        except Exception:
            raise ValueError("Wrong JWT format.")

        jwt._body_content._app_id = jwt._body_content.issuer.replace(jwt._body_content.subject_prefix, "")
        jwt._body_content._identity = jwt._body_content.subject.replace(jwt._body_content.identity_prefix, "")
        jwt._unsigned_data = str(parts[0] + "." + parts[1]).encode()
        jwt._string_representation = jwt_string
        return jwt

    def to_string(self):
        return self._string_representation

    def is_expired(self, expiration_timestamp=None):
        if not expiration_timestamp:
            expiration_time = datetime.datetime.utcnow()
        else:
            expiration_time = datetime.datetime.utcfromtimestamp(expiration_timestamp)
        return expiration_time >= self._body_content.expires_at

    @property
    def unsigned_data(self):
        return self._unsigned_data

    @property
    def signature_data(self):
        return self._signature_data

    @property
    def identity(self):
        return self._body_content.identity
