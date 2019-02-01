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
from collections import OrderedDict


class JwtHeaderContent(object):
    """JwtHeaderContent represents header of Jwt"""

    ACCESS_TOKEN_TYPE = "JWT"
    CONTENT_TYPE = "virgil-jwt;v=1"

    def __init__(
        self,
        algorithm,  # type: str
        key_id,  # type: str
        access_token_type=ACCESS_TOKEN_TYPE,  # type: str
        content_type=CONTENT_TYPE  # type: str
    ):
        self._algorithm = algorithm
        self._key_id = key_id
        self._access_token_type = access_token_type
        self._content_type = content_type

    def __eq__(self, other):
        return all([
            self.algorithm == other.algorithm,
            self.key_id == other.key_id,
            self.access_token_type == other.access_token_type,
            self.content_type == other.content_type
        ])

    @classmethod
    def from_json(cls, json_loaded_dict):
        # type: (Union[dict, str, bytes, bytearray]) -> JwtHeaderContent
        """
        Initializes a new instance of the JwtHeaderContent from json representation.

        Args:
            json_loaded_dict: JwtHeaderContent json representation

        Returns:
            A new instance of JwtHeaderContent.
        """
        header_content = cls.__new__(cls)
        header_content._algorithm = json_loaded_dict["alg"]
        header_content._access_token_type = json_loaded_dict["typ"]
        header_content._content_type = json_loaded_dict["cty"]
        header_content._key_id = json_loaded_dict["kid"]
        return header_content

    @property
    def json(self):
        """JwtHeaderContent json representation."""
        return OrderedDict({
            "alg": self.algorithm,
            "typ": self.access_token_type,
            "cty": self.content_type,
            "kid": self.key_id
        })

    @property
    def algorithm(self):
        """Signature algorithm."""
        return self._algorithm

    @property
    def key_id(self):
        """Id of public key which is used for jwt signature verification."""
        return self._key_id

    @property
    def access_token_type(self):
        """Access token type."""
        return self._access_token_type

    @property
    def content_type(self):
        """Access token content type."""
        return self._content_type
