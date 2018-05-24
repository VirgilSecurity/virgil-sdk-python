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
from base64 import b64encode, b64decode

from virgil_sdk.jwt.abstractions.access_token import AccessToken


class Jwt(AccessToken):

    def __init__(self, jwt_header_content=None, jwt_body_content=None, signature_data=None):
        self._header_content = jwt_header_content
        self._body_content = jwt_body_content
        self._signature_data = signature_data
        self._without_singature = b64encode(json.dumps(self._header_content) + "." + json.dumps(self._body_content))
        self._unsigned_data = b64decode(self._without_singature)
        self._string_representation = self._without_singature
        if self._signature_data:
            self._string_representation += "." + b64encode(self._signature_data)

    def __str__(self):
        return self._string_representation

    def __unicode__(self):
        return self._string_representation

    def __bytes__(self):
        return self._unsigned_data

    @classmethod
    def from_string(cls, jwt_string):
        parts = jwt_string.split(".")
        if len(parts) is not 3:
            raise ValueError("Wrong JWT format.")

        try:
            cls._header_content = json.loads(str(b64decode(parts[0])))
            cls._body_content = json.loads(str(b64decode(parts[1])))
            cls._signature_data = b64decode(parts[2])
        except Exception:
            raise ValueError("Wrong JWT format.")

        cls._body_content.app_id = cls._body_content.issuer.replace(cls._body_content.subject_prefix, "")
        cls._body_content.identity = cls._body_content.subject.replace(cls._body_content.identity_prefix, "")
        cls._unsigned_data = str(str(b64decode(parts[0])) + "." + str(b64decode(parts[1]))).encode()
        cls._string_representation = jwt_string
        return cls

    def to_string(self):
        return self._string_representation

    def is_expired(self, expiration_timestamp=None):
        if not expiration_timestamp:
            expiration_time = datetime.datetime.utcnow()
        else:
            expiration_time = datetime.datetime.fromtimestamp(expiration_timestamp)
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
