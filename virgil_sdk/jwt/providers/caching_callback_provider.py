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


class CachingCallbackProvider(AccessTokenProvider):
    """
    The CachingCallbackProvider class provides an opportunity to get cached access token
    or renew it using callback mechanism.
    """

    TOKEN_TTL = 5  # 5 seconds

    def __init__(
        self,
        renew_jwt_callback,  # type: function
        token_ttl=TOKEN_TTL,  # type: int
        initial_token=None  # type Jwt
    ):
        self._token_ttl = token_ttl
        self.__renew_jwt_callback = partial(renew_jwt_callback, token_ttl=token_ttl)
        self.__access_token = initial_token

    def get_token(self, token_context):
        # type: (TokenContext) -> Jwt
        """
        Gets access token from cache or renew by provided callback if expired.

        Args:
            token_context: Access token context.

        Returns:
            Instance of access token.
        """
        if self.__access_token:
            if not self.__access_token.is_expired() and not token_context.force_reload:
                return self.__access_token
        self.__access_token = Jwt.from_string(self.__renew_jwt_callback(token_context))
        return self.__access_token
