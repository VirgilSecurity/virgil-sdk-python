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
from .jwt_header_content import JwtHeaderContent


class JwtVerifier(object):
    """The JwtVerifier provides verification for Jwt."""

    def __init__(
            self,
            access_token_signer,
            api_public_key,
            api_public_key_id
    ):
        self._access_token_signer = access_token_signer
        self._api_public_key = api_public_key
        self._api_public_key_id = api_public_key_id

    def verify_token(self, jwt_token):
        # type: (Jwt) -> bool
        """
        To verify specified token.

        Args:
            jwt_token: An instance of Jwt to be verified.

        Returns:
            True if token is verified, otherwise False.
        """
        if jwt_token._header_content.key_id != self._api_public_key_id or\
           jwt_token._header_content.algorithm != self._access_token_signer.algorithm or\
           jwt_token._header_content.access_token_type != JwtHeaderContent.ACCESS_TOKEN_TYPE or\
           jwt_token._header_content.content_type != JwtHeaderContent.CONTENT_TYPE:
            return False
        return self._access_token_signer.verify_token_signature(
            bytearray(jwt_token.signature_data),
            bytearray(jwt_token.unsigned_data),
            self._api_public_key
        )
