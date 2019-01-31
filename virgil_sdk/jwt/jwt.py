# Copyright (C) 2016-2019 Virgil Security Inc.
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

from virgil_sdk.utils import Utils
from .jwt_header_content import JwtHeaderContent
from .jwt_body_content import JwtBodyContent
from virgil_sdk.jwt.abstractions.access_token import AccessToken


class Jwt(AccessToken):
    """
    The Jwt class implements abstract AccessToken in terms of Virgil JWT.
    """

    def __init__(
        self,
        jwt_header_content=None,  # type: JwtHeaderContent
        jwt_body_content=None,  # type: JwtBodyContent
        signature_data=None  # type: Union[bytes, bytearray]
    ):
        self._header_content = jwt_header_content
        self._body_content = jwt_body_content
        self._signature_data = signature_data
        self._without_signature = Utils.b64_encode(Utils.json_dumps(self._header_content.json, sort_keys=True).encode())\
                                  + "." +\
                                  Utils.b64_encode(Utils.json_dumps(self._body_content.json, sort_keys=True).encode())
        self._unsigned_data = self._without_signature.encode()
        self._string_representation = self._without_signature
        if self._signature_data:
            self._string_representation += "." + Utils.b64_encode(bytes(self._signature_data))

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
        # type: (str) -> Jwt
        """
        Initializes a new instance of the Jwt class using its string representation.

        Args:
            jwt_string: String representation of signed jwt. It must be equal to:
                base64UrlEncode(JWT Header) + "." + base64UrlEncode(JWT Body) "." + base64UrlEncode(Jwt Signature).

        Returns:
            Initialized instance of Jwt.

        Raises:
            ValueError: Wrong jwt format.
        """
        parts = jwt_string.split(".")
        if len(parts) is not 3:
            raise ValueError("Wrong JWT format.")

        try:
            jwt = cls.__new__(cls)
            jwt._header_content = JwtHeaderContent.from_json(Utils.json_loads(Utils.b64_decode(parts[0])))
            jwt._body_content = JwtBodyContent.from_json(Utils.json_loads(Utils.b64_decode(parts[1])))
            jwt._signature_data = bytearray(Utils.b64_decode(parts[2]))
        except Exception as e:
            raise ValueError("Wrong JWT format.")

        jwt._body_content._app_id = jwt._body_content.issuer.replace(jwt._body_content.subject_prefix, "")
        jwt._body_content._identity = jwt._body_content.subject.replace(jwt._body_content.identity_prefix, "")
        jwt._unsigned_data = bytearray(parts[0] + "." + parts[1], "utf-8")
        jwt._string_representation = jwt_string
        return jwt

    def to_string(self):
        """
        Jwt string representation.
        """
        return self._string_representation

    def is_expired(self, expiration_timestamp=None):
        """
        Whether or not token is expired.
        """
        if not expiration_timestamp:
            expiration_time = datetime.datetime.utcnow()
        else:
            expiration_time = datetime.datetime.utcfromtimestamp(expiration_timestamp)
        return expiration_time >= self._body_content.expires_at

    @property
    def unsigned_data(self):
        """
        String representation of jwt without signature.
        It equals to:
        base64UrlEncode(JWT Header) + "." + base64UrlEncode(JWT Body)
        """
        return self._unsigned_data

    @property
    def header_content(self):
        """Gets representation of jwt header"""
        return self._header_content

    @property
    def body_content(self):
        """Gets representation of jwt body"""
        return self._body_content

    @property
    def signature_data(self):
        """Gets a digital signature of jwt."""
        return self._signature_data

    @property
    def identity(self):
        """Jwt identity."""
        return self._body_content.identity
