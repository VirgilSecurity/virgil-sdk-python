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
from .base_request import BaseRequest


class Request(BaseRequest):
    """Http request wrapper.

    Args:
        endpoint: request endpoint
        body: request body
        headers: dict of request additional headers
        method: http request method
    """
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    DELETE = 'DELETE'

    def __init__(self, endpoint, body=None, method=GET, headers=None):
        # type: (str, Optional[str], Optional[str], Optional[dict]) -> None
        """Constructs new Request object."""
        self._endpoint = endpoint
        self._body = body
        self._headers = headers if headers else {}
        self._method = method

    def authorization(self, access_token):
        """
        Add authorization token to request.

        Args:
            access_token: Service access token.
        """
        self._headers.update({"Authorization": "Virgil {}".format(access_token)})

    @property
    def endpoint(self):
        """
        Gets the endpoint. Does not include server base address
        """
        return self._endpoint

    @property
    def body(self):
        """
        Gets the requests body.
        """
        return self._body

    @property
    def headers(self):
        """
        Gets the http headers.
        """
        return self._headers

    @property
    def method(self):
        """
        Gets the request method.
        """
        return self._method
