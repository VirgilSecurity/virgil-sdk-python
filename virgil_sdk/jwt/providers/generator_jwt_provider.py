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
from functools import partial

from virgil_sdk.jwt import Jwt
from virgil_sdk.jwt.abstractions.access_token_provider import AccessTokenProvider


class GeneratorJwtProvider(AccessTokenProvider):
    """
    Implementation of AccessTokenProvider which provides generated JWTs
    """

    def __init__(
        self,
        jwt_generator,  # type: JwtGenerator
        default_identity,  # type: str
        additional_data=None  # type: Union[None, dict]
    ):
        self.jwt_generator = jwt_generator
        self.default_identity = default_identity
        self.additional_data = additional_data

    def get_token(self, token_context):
        # type: (TokenContext) -> Jwt
        """
        Provides new generated JWT

        Args:
            token_context: context explaining why token is needed

        Returns:
            generated jwt
        """
        if token_context.identity:
            identity = token_context.identity
        else:
            identity = self.default_identity
        token = self.jwt_generator.generate_token(identity, self.additional_data)
        return token
