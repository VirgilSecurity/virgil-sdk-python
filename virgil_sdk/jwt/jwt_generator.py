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

from .jwt import Jwt
from .jwt_header_content import JwtHeaderContent
from .jwt_body_content import JwtBodyContent


class JwtGenerator(object):

    def __init__(
        self,
        app_id,
        api_key,
        api_public_key_id,
        lifetime,
        access_token_signer
    ):
        self._app_id = app_id
        self._api_key = api_key
        self._lifetime = lifetime
        self._api_public_key_id = api_public_key_id
        self._access_token_signer = access_token_signer

    def generate_token(self, identity, data=None):
        issued_at = datetime.datetime.utcnow()
        expires_at = datetime.datetime.fromtimestamp(issued_at.timestamp() + self._lifetime)
        jwt_body = JwtBodyContent(
            self._app_id,
            identity,
            issued_at,
            expires_at,
            data
        )
        jwt_header = JwtHeaderContent(
            self._access_token_signer.algorithm,
            self._api_public_key_id
        )
        unsigned_jwt = Jwt(jwt_header, jwt_body).unsigned_data
        jwt_bytes = unsigned_jwt
        signature = self._access_token_signer.generate_token_signature(jwt_bytes, self._api_key)
        return Jwt(jwt_header, jwt_body, bytes(signature))
